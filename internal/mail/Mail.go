// Package mail delivers outbound notification email through a pluggable
// connector. Two connectors are provided: plain SMTP, and Azure Communication
// Services Email over its REST API.
//
// Azure's SMTP relay is deliberately not the Azure path here. Using it
// requires an Entra application registration and a composite SMTP username of
// the form <resource>.<application-id>.<tenant-id>, which is awkward to
// configure and easy to get wrong. The REST connector needs only the
// connection string that the Azure portal shows on the resource's Keys blade,
// so it is the supported way to reach Azure.
package mail

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// ErrNotConfigured is returned by Send when no mail connector is configured.
// Callers that treat email as optional should check for it explicitly rather
// than failing the whole operation.
var ErrNotConfigured = errors.New("mail: no connector configured")

// Message is a single outbound email. Text is mandatory: a message with only
// an HTML body is treated as malformed, because a recipient whose client
// refuses HTML would otherwise receive an empty message.
type Message struct {
	To      []string
	Subject string
	Text    string
	Html    string
}

// Sender delivers a Message. Implementations must be safe for concurrent use
// by multiple goroutines.
type Sender interface {
	// Send delivers the message, honouring cancellation through ctx.
	Send(ctx context.Context, msg Message) (Receipt, error)
	// Name identifies the connector for logs and the status view.
	Name() string
}

// Receipt carries whatever delivery correlation id the connector produced, so
// a caller that audits the send can later take it to the connector's own
// portal or log and ask "was this delivered". MessageId is empty when the
// connector offers nothing to correlate with.
type Receipt struct {
	MessageId string
}

// Validate reports whether the message can be sent. It rejects header
// injection: a subject or address containing a carriage return or newline
// could otherwise terminate the header and inject arbitrary headers or an
// entire second message into the SMTP conversation.
func (m Message) Validate() error {
	if len(m.To) == 0 {
		return errors.New("mail: no recipient")
	}
	for _, address := range m.To {
		if containsNewline(address) {
			return fmt.Errorf("mail: recipient %q contains a line break", address)
		}
		if _, err := netMailParse(address); err != nil {
			return fmt.Errorf("mail: recipient %q is not a valid address: %w", address, err)
		}
	}
	if strings.TrimSpace(m.Subject) == "" {
		return errors.New("mail: empty subject")
	}
	if containsNewline(m.Subject) {
		return errors.New("mail: subject contains a line break")
	}
	if strings.TrimSpace(m.Text) == "" {
		return errors.New("mail: empty text body")
	}
	return nil
}

func containsNewline(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

func netMailParse(address string) (*mail.Address, error) {
	return mail.ParseAddress(address)
}

// New builds the connector named by the configuration. An unknown provider is
// an error rather than a silent fallback to disabled: a typo in
// GOKAPI_MAIL_PROVIDER must not quietly turn notifications off.
func New(config Config) (Sender, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	switch config.NormalisedProvider() {
	case ProviderDisabled:
		return disabledSender{}, nil
	case ProviderLog:
		return newLogSender(config), nil
	case ProviderSmtp:
		return newSmtpSender(config)
	case ProviderAzure:
		return newAzureSender(config)
	default:
		return nil, fmt.Errorf("mail: unknown provider %q, expected one of %s",
			config.Provider, strings.Join(AllProviders, ", "))
	}
}

// disabledSender is the connector used when email is switched off. It reports
// ErrNotConfigured rather than pretending to succeed, so that a caller which
// depends on delivery can surface the misconfiguration instead of silently
// dropping a message a user was told had been sent.
type disabledSender struct{}

func (disabledSender) Name() string { return ProviderDisabled }

func (disabledSender) Send(_ context.Context, _ Message) (Receipt, error) {
	return Receipt{}, ErrNotConfigured
}
