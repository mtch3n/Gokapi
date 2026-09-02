package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"time"
)

// smtpSender delivers over SMTP using the standard library.
type smtpSender struct {
	config  Config
	from    mail.Address
	address string
	timeout time.Duration
}

func newSmtpSender(config Config) (Sender, error) {
	from, err := config.senderAddress()
	if err != nil {
		return nil, err
	}
	return &smtpSender{
		config:  config,
		from:    from,
		address: net.JoinHostPort(config.SmtpHost, strconv.Itoa(config.SmtpPort)),
		timeout: time.Duration(config.TimeoutSeconds) * time.Second,
	}, nil
}

func (s *smtpSender) Name() string { return ProviderSmtp }

func (s *smtpSender) Send(ctx context.Context, msg Message) (Receipt, error) {
	body, messageId, err := buildMime(s.from, msg, time.Now())
	if err != nil {
		return Receipt{}, err
	}

	// net/smtp predates context and offers no cancellation of its own. The
	// deadline is therefore applied to the connection, which is what actually
	// blocks, and the context is checked at the start so an already-cancelled
	// caller does not open a socket at all.
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	deadline := time.Now().Add(s.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	conn, err := s.dial(deadline)
	if err != nil {
		return Receipt{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		return Receipt{}, fmt.Errorf("mail: cannot set the connection deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, s.config.SmtpHost)
	if err != nil {
		return Receipt{}, fmt.Errorf("mail: SMTP handshake with %s failed: %w", s.address, err)
	}
	defer func() { _ = client.Close() }()

	if s.config.NormalisedEncryption() == EncryptionStartTls {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return Receipt{}, fmt.Errorf("mail: %s does not offer STARTTLS. Set GOKAPI_MAIL_SMTP_ENCRYPTION=tls for an implicit-TLS port such as 465, or =none with GOKAPI_MAIL_SMTP_ALLOW_INSECURE=true for a local test relay", s.address)
		}
		if err := client.StartTLS(s.tlsConfig()); err != nil {
			return Receipt{}, fmt.Errorf("mail: STARTTLS with %s failed: %w", s.address, err)
		}
	}

	if s.config.SmtpUsername != "" {
		if err := client.Auth(s.authMechanism(client)); err != nil {
			return Receipt{}, fmt.Errorf("mail: SMTP authentication as %s failed: %w", s.config.SmtpUsername, err)
		}
	}

	if err := client.Mail(s.from.Address); err != nil {
		return Receipt{}, fmt.Errorf("mail: MAIL FROM %s rejected: %w", s.from.Address, err)
	}
	for _, recipient := range msg.To {
		// The envelope takes the bare address. Message.Validate accepts the
		// name-addr form too ("Bob <bob@example.com>"), which would otherwise
		// be handed to RCPT TO verbatim and rejected by the server.
		parsed, err := mail.ParseAddress(recipient)
		if err != nil {
			return Receipt{}, fmt.Errorf("mail: recipient %q is not a valid address: %w", recipient, err)
		}
		if err := client.Rcpt(parsed.Address); err != nil {
			return Receipt{}, fmt.Errorf("mail: RCPT TO %s rejected: %w", parsed.Address, err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return Receipt{}, fmt.Errorf("mail: DATA rejected: %w", err)
	}
	if _, err := writer.Write(body); err != nil {
		return Receipt{}, fmt.Errorf("mail: writing the message body failed: %w", err)
	}
	if err := writer.Close(); err != nil {
		return Receipt{}, fmt.Errorf("mail: the server rejected the message: %w", err)
	}
	// The server accepted the message at this point. A failure to close the
	// conversation cleanly is not a delivery failure, and reporting one would
	// make a retrying caller send the message twice.
	_ = client.Quit()
	return Receipt{MessageId: messageId}, nil
}

func (s *smtpSender) dial(deadline time.Time) (net.Conn, error) {
	dialer := &net.Dialer{Deadline: deadline}
	if s.config.NormalisedEncryption() == EncryptionTls {
		conn, err := tls.DialWithDialer(dialer, "tcp", s.address, s.tlsConfig())
		if err != nil {
			return nil, fmt.Errorf("mail: TLS connection to %s failed: %w", s.address, err)
		}
		return conn, nil
	}
	conn, err := dialer.Dial("tcp", s.address)
	if err != nil {
		return nil, fmt.Errorf("mail: connection to %s failed: %w", s.address, err)
	}
	return conn, nil
}

func (s *smtpSender) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName: s.config.SmtpHost,
		// Only ever true when the operator has explicitly opted in. Validate
		// refuses to combine this with a username in any encryption mode, so
		// no credential is ever sent to an unauthenticated peer.
		InsecureSkipVerify: s.config.SmtpAllowInsecure,
		MinVersion:         tls.VersionTLS12,
	}
}

// authMechanism picks an SMTP AUTH mechanism. PLAIN is preferred, but a
// notable set of servers, Office 365 and Azure's own SMTP relay among them,
// advertise only LOGIN. net/smtp ships no LOGIN implementation, so loginAuth
// below supplies one.
func (s *smtpSender) authMechanism(client *smtp.Client) smtp.Auth {
	if _, mechanisms := client.Extension("AUTH"); mechanisms != "" {
		if !containsMechanism(mechanisms, "PLAIN") && containsMechanism(mechanisms, "LOGIN") {
			return &loginAuth{username: s.config.SmtpUsername, password: s.config.SmtpPassword, host: s.config.SmtpHost}
		}
	}
	return smtp.PlainAuth("", s.config.SmtpUsername, s.config.SmtpPassword, s.config.SmtpHost)
}

func containsMechanism(advertised, mechanism string) bool {
	for _, candidate := range splitFields(advertised) {
		if candidate == mechanism {
			return true
		}
	}
	return false
}

// loginAuth implements the non-standard but widely required AUTH LOGIN
// mechanism, in which the username and password are sent as two separate
// base64 challenges.
type loginAuth struct {
	username string
	password string
	host     string
}

// Start refuses to run over an unencrypted connection. AUTH LOGIN transmits
// the password in base64, which is encoding and not encryption, so without TLS
// the credential is effectively in the clear. smtp.PlainAuth makes the same
// check; matching it here keeps the two mechanisms equally safe.
func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("mail: refusing to send AUTH LOGIN credentials over an unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, fmt.Errorf("mail: SMTP server name %q does not match the configured host %q", server.Name, a.host)
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch string(fromServer) {
	case "Username:", "username:", "User Name\x00":
		return []byte(a.username), nil
	case "Password:", "password:", "Password\x00":
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("mail: unexpected AUTH LOGIN challenge %q", fromServer)
	}
}

func splitFields(value string) []string {
	var fields []string
	current := ""
	for _, r := range value {
		if r == ' ' || r == ',' || r == '\t' {
			if current != "" {
				fields = append(fields, current)
				current = ""
			}
			continue
		}
		current += string(r)
	}
	if current != "" {
		fields = append(fields, current)
	}
	return fields
}
