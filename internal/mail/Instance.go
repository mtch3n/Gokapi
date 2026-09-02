package mail

import (
	"context"
	"fmt"
	"sync"
	"time"
)

var (
	instanceMutex  sync.RWMutex
	instance       Sender
	instanceConfig Config
)

// Init builds the configured connector and stores it as the process-wide
// sender. It returns an error rather than calling log.Fatal, so that the
// caller decides whether a mail misconfiguration should stop the server. It
// should not: a file exchange that cannot send a notification is degraded, not
// broken, and refusing to boot would turn a typo in a mail variable into an
// outage.
func Init() error {
	config, err := NewConfigFromEnv()
	if err != nil {
		return err
	}
	return InitWithConfig(config)
}

// InitWithConfig is Init against an explicit configuration. Used by tests.
func InitWithConfig(config Config) error {
	sender, err := New(config)
	if err != nil {
		return err
	}
	instanceMutex.Lock()
	defer instanceMutex.Unlock()
	instance = sender
	instanceConfig = config
	return nil
}

// Get returns the configured sender. It never returns nil: before Init runs,
// or after an Init that failed, it reports the disabled connector, so a caller
// gets ErrNotConfigured instead of a nil dereference.
func Get() Sender {
	instanceMutex.RLock()
	defer instanceMutex.RUnlock()
	if instance == nil {
		return disabledSender{}
	}
	return instance
}

// GetConfig returns the configuration the current sender was built from.
func GetConfig() Config {
	instanceMutex.RLock()
	defer instanceMutex.RUnlock()
	return instanceConfig
}

// IsEnabled reports whether a real connector is active.
func IsEnabled() bool {
	return Get().Name() != ProviderDisabled
}

// Send delivers a message through the configured sender, applying the
// configured timeout when the caller supplies no deadline of its own.
func Send(ctx context.Context, msg Message) (Receipt, error) {
	sender := Get()
	config := GetConfig()
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && config.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(config.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	return sender.Send(ctx, msg)
}

// SendTest delivers a fixed message, so an operator can prove the
// configuration works without waiting for a real event to fire. This is the
// only way to distinguish "configured correctly" from "configured, untested"
// before the first real notification goes out.
func SendTest(ctx context.Context, recipient string) (Receipt, error) {
	sender := Get()
	if sender.Name() == ProviderDisabled {
		return Receipt{}, ErrNotConfigured
	}
	return Send(ctx, Message{
		To:      []string{recipient},
		Subject: "gokapi mail configuration test",
		Text: fmt.Sprintf(
			"This is a test message sent through the %s connector at %s.\r\n\r\n"+
				"If you received it, outbound mail is configured correctly.\r\n",
			sender.Name(), time.Now().Format(time.RFC1123)),
	})
}

// ResetForTesting clears the process-wide sender.
func ResetForTesting() {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()
	instance = nil
	instanceConfig = Config{}
}
