package mail

import (
	"context"
	"fmt"
	"log"
	"time"
)

// logSender records that a message would have been sent, instead of delivering
// it. It exists so a flow that sends mail can be exercised end to end during
// development without a mail account, and so the pre-go-live drills can prove
// the call site is reached.
//
// It logs the recipient and subject but NOT the body. The body now carries a
// recipient's access link, which is a bearer credential: anyone who can read
// the log could open the share. Logs are rotated, shipped and read by whoever
// is debugging, so this is not a safe place for one even in development.
type logSender struct {
	config Config
}

func newLogSender(config Config) Sender {
	return &logSender{config: config}
}

func (l *logSender) Name() string { return ProviderLog }

func (l *logSender) Send(_ context.Context, msg Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	log.Printf("mail(log connector): at=%s to=%v subject=%q bodyBytes=%d (body withheld, it may contain an access link)",
		time.Now().Format(time.RFC3339), msg.To, msg.Subject, len(msg.Text))
	return nil
}

// Describe renders a one-line summary of a connector for the status view.
func Describe(sender Sender, config Config) string {
	if sender == nil {
		return "mail: not initialised"
	}
	return fmt.Sprintf("mail: connector=%s %s", sender.Name(), config.Redacted())
}
