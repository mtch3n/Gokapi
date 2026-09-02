package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
)

// buildMime renders the message as an RFC 5322 document suitable for handing
// to an SMTP server. A message with an HTML body is sent as
// multipart/alternative with the plain-text part first, which is the order
// RFC 2046 requires: a client picks the last part it understands, so the
// richest representation has to come last.
//
// now is injected so that tests can assert on a fixed Date header.
//
// The Message-ID it generates is returned alongside the rendered document, so
// a caller that hands the bytes to an SMTP server can still correlate the
// send afterwards - the header could otherwise only be recovered by parsing
// the document back out.
func buildMime(from mail.Address, msg Message, now time.Time) ([]byte, string, error) {
	if err := msg.Validate(); err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	writeHeader(&buf, "From", from.String())
	writeHeader(&buf, "To", strings.Join(msg.To, ", "))
	writeHeader(&buf, "Subject", encodeHeaderValue(msg.Subject))
	writeHeader(&buf, "Date", now.Format(time.RFC1123Z))
	messageId, err := generateMessageId(from.Address)
	if err != nil {
		return nil, "", err
	}
	writeHeader(&buf, "Message-ID", messageId)
	writeHeader(&buf, "MIME-Version", "1.0")
	// These messages tell a named person that a file is waiting. An auto
	// reply or an out-of-office bounce back to the sending address serves no
	// purpose and would land in an unmonitored mailbox.
	writeHeader(&buf, "Auto-Submitted", "auto-generated")

	if msg.Html == "" {
		writeHeader(&buf, "Content-Type", `text/plain; charset="utf-8"`)
		writeHeader(&buf, "Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		if err := writeQuotedPrintable(&buf, msg.Text); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), messageId, nil
	}

	boundary, err := generateBoundary()
	if err != nil {
		return nil, "", err
	}
	writeHeader(&buf, "Content-Type", fmt.Sprintf(`multipart/alternative; boundary="%s"`, boundary))
	buf.WriteString("\r\n")

	for _, part := range []struct{ contentType, body string }{
		{`text/plain; charset="utf-8"`, msg.Text},
		{`text/html; charset="utf-8"`, msg.Html},
	} {
		fmt.Fprintf(&buf, "--%s\r\n", boundary)
		writeHeader(&buf, "Content-Type", part.contentType)
		writeHeader(&buf, "Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		if err := writeQuotedPrintable(&buf, part.body); err != nil {
			return nil, "", err
		}
		buf.WriteString("\r\n")
	}
	fmt.Fprintf(&buf, "--%s--\r\n", boundary)
	return buf.Bytes(), messageId, nil
}

func writeHeader(buf *bytes.Buffer, name, value string) {
	fmt.Fprintf(buf, "%s: %s\r\n", name, value)
}

// encodeHeaderValue applies RFC 2047 encoded-word encoding when the value is
// not pure ASCII, so that a non-ASCII subject survives transport. mime.QEncoding
// leaves an ASCII-only value untouched.
func encodeHeaderValue(value string) string {
	return mime.QEncoding.Encode("utf-8", value)
}

// writeQuotedPrintable encodes the body. Quoted-printable is used rather than
// raw 8-bit because it also solves SMTP's line-length limit and protects a
// line that would otherwise begin with a bare "." and be read as the
// end-of-data marker.
func writeQuotedPrintable(buf *bytes.Buffer, body string) error {
	writer := quotedprintable.NewWriter(buf)
	if _, err := writer.Write([]byte(normaliseLineEndings(body))); err != nil {
		return err
	}
	return writer.Close()
}

// normaliseLineEndings converts every line ending to CRLF. A body assembled in
// Go typically uses bare LF, which some strict servers reject.
func normaliseLineEndings(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	return strings.ReplaceAll(body, "\n", "\r\n")
}

func generateBoundary() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mail: cannot generate a MIME boundary: %w", err)
	}
	return "gokapi-" + hex.EncodeToString(raw), nil
}

// generateMessageId builds a globally unique Message-ID, using the sender
// domain as the right-hand side so it reads as originating from this system.
func generateMessageId(fromAddress string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mail: cannot generate a Message-ID: %w", err)
	}
	domain := "localhost"
	if _, host, found := strings.Cut(fromAddress, "@"); found && host != "" {
		domain = host
	}
	return fmt.Sprintf("<%s@%s>", hex.EncodeToString(raw), domain), nil
}

// senderAddress builds the From address from the configuration.
func (c Config) senderAddress() (mail.Address, error) {
	parsed, err := mail.ParseAddress(c.FromAddress)
	if err != nil {
		return mail.Address{}, fmt.Errorf("mail: invalid sender address: %w", err)
	}
	name := strings.TrimSpace(c.FromName)
	if name != "" {
		parsed.Name = name
	}
	return *parsed, nil
}
