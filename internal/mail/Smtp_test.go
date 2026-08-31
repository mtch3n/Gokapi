//go:build test

package mail

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"

	"github.com/forceu/gokapi/internal/test"
)

// fakeSmtpServer is a minimal SMTP server, enough to complete one delivery.
// It records the conversation so a test can assert on the envelope and the
// rendered message, which a mock of net/smtp could not do.
type fakeSmtpServer struct {
	listener net.Listener
	mutex    sync.Mutex
	from     string
	to       []string
	data     string
	done     chan struct{}
	// advertiseAuth is echoed in the EHLO response, so a test can choose
	// which AUTH mechanisms the server appears to support.
	advertiseAuth string
	authLines     []string
}

func newFakeSmtpServer(t *testing.T, advertiseAuth string) *fakeSmtpServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	test.IsNil(t, err)
	server := &fakeSmtpServer{listener: listener, done: make(chan struct{}), advertiseAuth: advertiseAuth}
	go server.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func (s *fakeSmtpServer) hostPort() (string, int) {
	address := s.listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", address.Port
}

func (s *fakeSmtpServer) serve() {
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	defer close(s.done)

	reader := bufio.NewReader(conn)
	write := func(format string, args ...any) {
		_, _ = fmt.Fprintf(conn, format+"\r\n", args...)
	}

	write("220 fake.example.com ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(command, "EHLO"):
			write("250-fake.example.com")
			if s.advertiseAuth != "" {
				write("250-AUTH %s", s.advertiseAuth)
			}
			write("250 SIZE 35882577")
		case strings.HasPrefix(command, "HELO"):
			write("250 fake.example.com")
		case strings.HasPrefix(command, "AUTH"):
			s.mutex.Lock()
			s.authLines = append(s.authLines, strings.TrimSpace(line))
			s.mutex.Unlock()
			if strings.Contains(command, "AUTH LOGIN") {
				// Base64 of "Username:" then "Password:".
				write("334 VXNlcm5hbWU6")
				userLine, _ := reader.ReadString('\n')
				s.mutex.Lock()
				s.authLines = append(s.authLines, strings.TrimSpace(userLine))
				s.mutex.Unlock()
				write("334 UGFzc3dvcmQ6")
				passLine, _ := reader.ReadString('\n')
				s.mutex.Lock()
				s.authLines = append(s.authLines, strings.TrimSpace(passLine))
				s.mutex.Unlock()
			}
			write("235 2.7.0 Authentication successful")
		case strings.HasPrefix(command, "MAIL FROM:"):
			s.mutex.Lock()
			s.from = extractAddress(line)
			s.mutex.Unlock()
			write("250 OK")
		case strings.HasPrefix(command, "RCPT TO:"):
			s.mutex.Lock()
			s.to = append(s.to, extractAddress(line))
			s.mutex.Unlock()
			write("250 OK")
		case command == "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			var builder strings.Builder
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
				builder.WriteString(dataLine)
			}
			s.mutex.Lock()
			s.data = builder.String()
			s.mutex.Unlock()
			write("250 OK queued")
		case command == "QUIT":
			write("221 Bye")
			return
		case command == "RSET" || command == "NOOP":
			write("250 OK")
		default:
			write("500 Unrecognised command")
		}
	}
}

func extractAddress(line string) string {
	start := strings.Index(line, "<")
	end := strings.Index(line, ">")
	if start == -1 || end == -1 || end < start {
		return strings.TrimSpace(line)
	}
	return line[start+1 : end]
}

func (s *fakeSmtpServer) captured() (string, []string, string) {
	<-s.done
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.from, s.to, s.data
}

// A full delivery over an unencrypted local connection, which is the mode a
// developer running MailHog would use.
func TestSmtpSendDelivers(t *testing.T) {
	server := newFakeSmtpServer(t, "")
	host, port := server.hostPort()

	sender, err := New(Config{
		Provider: ProviderSmtp, FromAddress: "no-reply@example.com", FromName: "ExchangePoint",
		SmtpHost: host, SmtpPort: port, SmtpEncryption: EncryptionNone,
		SmtpAllowInsecure: true, TimeoutSeconds: 20,
	})
	test.IsNil(t, err)

	msg := validMessage()
	msg.To = []string{"one@example.com", "two@example.com"}
	test.IsNil(t, sender.Send(context.Background(), msg))

	from, to, data := server.captured()
	test.IsEqualString(t, from, "no-reply@example.com")
	test.IsEqualInt(t, len(to), 2)
	test.IsEqualString(t, to[0], "one@example.com")
	test.IsEqualString(t, to[1], "two@example.com")

	for _, expected := range []string{
		"Subject: A file is waiting for you",
		"To: one@example.com, two@example.com",
		`From: "ExchangePoint" <no-reply@example.com>`,
	} {
		if !strings.Contains(data, expected) {
			t.Errorf("delivered message is missing %q\ngot:\n%s", expected, data)
		}
	}
}

// STARTTLS is the default, so a server that does not offer it must produce an
// error that names the fix rather than silently downgrading to plaintext.
func TestSmtpRefusesToDowngradeFromStartTls(t *testing.T) {
	server := newFakeSmtpServer(t, "")
	host, port := server.hostPort()

	sender, err := New(Config{
		Provider: ProviderSmtp, FromAddress: "no-reply@example.com",
		SmtpHost: host, SmtpPort: port, SmtpEncryption: EncryptionStartTls,
		TimeoutSeconds: 20,
	})
	test.IsNil(t, err)

	err = sender.Send(context.Background(), validMessage())
	test.IsNotNil(t, err)
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("the error must name STARTTLS as the problem, got: %v", err)
	}
}

func TestSmtpValidatesMessageBeforeConnecting(t *testing.T) {
	sender, err := New(Config{
		Provider: ProviderSmtp, FromAddress: "no-reply@example.com",
		// A port nothing listens on: reaching the dial at all is the failure.
		SmtpHost: "127.0.0.1", SmtpPort: 1, SmtpEncryption: EncryptionNone,
		SmtpAllowInsecure: true, TimeoutSeconds: 20,
	})
	test.IsNil(t, err)

	bad := validMessage()
	bad.To = []string{"not-an-address"}
	err = sender.Send(context.Background(), bad)
	test.IsNotNil(t, err)
	if !strings.Contains(err.Error(), "not a valid address") {
		t.Errorf("expected validation to fail before dialling, got: %v", err)
	}
}

func TestSmtpHonoursCancelledContext(t *testing.T) {
	sender, err := New(Config{
		Provider: ProviderSmtp, FromAddress: "no-reply@example.com",
		SmtpHost: "127.0.0.1", SmtpPort: 1, SmtpEncryption: EncryptionNone,
		SmtpAllowInsecure: true, TimeoutSeconds: 20,
	})
	test.IsNil(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	test.IsEqual(t, sender.Send(ctx, validMessage()), context.Canceled)
}

// AUTH LOGIN must be refused without TLS: the credential is base64, which is
// encoding and not encryption. This mirrors what smtp.PlainAuth enforces.
func TestLoginAuthRequiresTls(t *testing.T) {
	auth := &loginAuth{username: "user", password: "pw", host: "smtp.example.com"}

	_, _, err := auth.Start(smtpServerInfo(false, "smtp.example.com"))
	test.IsNotNil(t, err)

	proto, initial, err := auth.Start(smtpServerInfo(true, "smtp.example.com"))
	test.IsNil(t, err)
	test.IsEqualString(t, proto, "LOGIN")
	test.IsEqualInt(t, len(initial), 0)

	t.Run("refuses a host mismatch", func(t *testing.T) {
		_, _, err := auth.Start(smtpServerInfo(true, "evil.example.com"))
		test.IsNotNil(t, err)
	})

	t.Run("answers the two challenges", func(t *testing.T) {
		reply, err := auth.Next([]byte("Username:"), true)
		test.IsNil(t, err)
		test.IsEqualString(t, string(reply), "user")

		reply, err = auth.Next([]byte("Password:"), true)
		test.IsNil(t, err)
		test.IsEqualString(t, string(reply), "pw")
	})

	t.Run("rejects an unexpected challenge", func(t *testing.T) {
		_, err := auth.Next([]byte("Surname:"), true)
		test.IsNotNil(t, err)
	})
}

// smtpServerInfo builds the server description net/smtp hands to an Auth.
func smtpServerInfo(usingTls bool, name string) *smtp.ServerInfo {
	return &smtp.ServerInfo{Name: name, TLS: usingTls}
}

func TestSplitFields(t *testing.T) {
	test.IsEqual(t, splitFields("PLAIN LOGIN CRAM-MD5"), []string{"PLAIN", "LOGIN", "CRAM-MD5"})
	test.IsEqual(t, splitFields("LOGIN"), []string{"LOGIN"})
	test.IsEqualInt(t, len(splitFields("")), 0)
}

func TestContainsMechanism(t *testing.T) {
	test.IsEqualBool(t, containsMechanism("PLAIN LOGIN", "LOGIN"), true)
	test.IsEqualBool(t, containsMechanism("PLAIN LOGIN", "PLAIN"), true)
	test.IsEqualBool(t, containsMechanism("PLAIN", "LOGIN"), false)
	// A prefix must not count as a match.
	test.IsEqualBool(t, containsMechanism("LOGINX", "LOGIN"), false)
}
