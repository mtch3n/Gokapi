package mail

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	envParser "github.com/caarlos0/env/v6"
)

// Provider names accepted by GOKAPI_MAIL_PROVIDER.
const (
	// ProviderDisabled switches outbound mail off. This is the default.
	ProviderDisabled = "disabled"
	// ProviderLog writes the message to the log instead of sending it. For
	// development, so that a flow which sends mail can be exercised end to
	// end without a mail account.
	ProviderLog = "log"
	// ProviderSmtp delivers over SMTP.
	ProviderSmtp = "smtp"
	// ProviderAzure delivers through the Azure Communication Services Email
	// REST API.
	ProviderAzure = "azure"
)

// AllProviders lists every accepted provider, for error messages.
var AllProviders = []string{ProviderDisabled, ProviderLog, ProviderSmtp, ProviderAzure}

// SMTP transport security modes accepted by GOKAPI_MAIL_SMTP_ENCRYPTION.
const (
	// EncryptionStartTls connects in the clear and upgrades with STARTTLS.
	// This is the default and what port 587 expects.
	EncryptionStartTls = "starttls"
	// EncryptionTls opens a TLS connection immediately. Port 465.
	EncryptionTls = "tls"
	// EncryptionNone sends in the clear. Only honoured together with
	// AllowInsecure, and never carries credentials.
	EncryptionNone = "none"
)

// Config holds every mail setting. It is parsed from the environment rather
// than being folded into environment.Environment on purpose: it carries
// credentials, and Environment is reflected over for the persistent-value
// mechanism and rendered into the generated docs/advanced.rst table. Keeping
// the secrets in their own struct keeps them out of both.
type Config struct {
	// Provider selects the connector. See AllProviders.
	Provider string `env:"MAIL_PROVIDER" envDefault:"disabled"`
	// FromAddress is the envelope and header sender. Required unless the
	// provider is disabled or log.
	FromAddress string `env:"MAIL_FROM"`
	// FromName is the display name shown beside the sender address.
	FromName string `env:"MAIL_FROM_NAME" envDefault:""`
	// TimeoutSeconds bounds a single delivery attempt.
	TimeoutSeconds int `env:"MAIL_TIMEOUT_SECONDS" envDefault:"20"`

	// SmtpHost is the mail server hostname. Required for the smtp provider.
	SmtpHost string `env:"MAIL_SMTP_HOST"`
	// SmtpPort is the mail server port.
	SmtpPort int `env:"MAIL_SMTP_PORT" envDefault:"587"`
	// SmtpUsername is the SMTP AUTH username. Empty means no authentication.
	SmtpUsername string `env:"MAIL_SMTP_USERNAME"`
	// SmtpPassword is the SMTP AUTH password.
	SmtpPassword string `env:"MAIL_SMTP_PASSWORD"`
	// SmtpEncryption selects the transport security mode.
	SmtpEncryption string `env:"MAIL_SMTP_ENCRYPTION" envDefault:"starttls"`
	// SmtpAllowInsecure permits an unencrypted connection, and permits a TLS
	// connection whose certificate does not verify. Both are refused without
	// it. Intended for a local test relay such as MailHog, never production.
	SmtpAllowInsecure bool `env:"MAIL_SMTP_ALLOW_INSECURE" envDefault:"false"`

	// AzureConnectionString is the value shown on the Communication Services
	// resource's Keys blade, in the form
	// endpoint=https://<name>.communication.azure.com/;accesskey=<base64>
	// Setting it populates AzureEndpoint and AzureAccessKey.
	AzureConnectionString string `env:"MAIL_AZURE_CONNECTION_STRING"`
	// AzureEndpoint is the resource endpoint, if supplied separately.
	AzureEndpoint string `env:"MAIL_AZURE_ENDPOINT"`
	// AzureAccessKey is the base64 access key, if supplied separately.
	AzureAccessKey string `env:"MAIL_AZURE_ACCESS_KEY"`
}

// NewConfigFromEnv reads the mail configuration from GOKAPI_MAIL_* variables.
func NewConfigFromEnv() (Config, error) {
	var result Config
	err := envParser.Parse(&result, envParser.Options{Prefix: "GOKAPI_"})
	if err != nil {
		return Config{}, fmt.Errorf("mail: cannot parse environment: %w", err)
	}
	return result, nil
}

// NormalisedProvider returns the provider lowercased and trimmed, with the
// empty value treated as disabled.
func (c Config) NormalisedProvider() string {
	provider := strings.ToLower(strings.TrimSpace(c.Provider))
	if provider == "" {
		return ProviderDisabled
	}
	return provider
}

// NormalisedEncryption returns the SMTP transport mode lowercased and
// trimmed, with the empty value treated as STARTTLS.
func (c Config) NormalisedEncryption() string {
	encryption := strings.ToLower(strings.TrimSpace(c.SmtpEncryption))
	if encryption == "" {
		return EncryptionStartTls
	}
	return encryption
}

// IsEnabled reports whether a real connector is configured.
func (c Config) IsEnabled() bool {
	return c.NormalisedProvider() != ProviderDisabled
}

// Validate checks the settings the selected provider actually needs, so that
// a misconfiguration is reported at startup rather than at the moment a user
// action depends on an email going out.
func (c Config) Validate() error {
	provider := c.NormalisedProvider()
	if provider == ProviderDisabled {
		return nil
	}
	// The provider name is checked first so that a typo reports itself.
	// Checking the shared settings first would blame a missing GOKAPI_MAIL_FROM
	// for what is really an unrecognised GOKAPI_MAIL_PROVIDER.
	if !isKnownProvider(provider) {
		return fmt.Errorf("mail: unknown provider %q, expected one of %s",
			c.Provider, strings.Join(AllProviders, ", "))
	}
	if c.TimeoutSeconds <= 0 {
		return errors.New("mail: GOKAPI_MAIL_TIMEOUT_SECONDS must be positive")
	}
	if provider != ProviderLog {
		if strings.TrimSpace(c.FromAddress) == "" {
			return errors.New("mail: GOKAPI_MAIL_FROM is required")
		}
		if _, err := mail.ParseAddress(c.FromAddress); err != nil {
			return fmt.Errorf("mail: GOKAPI_MAIL_FROM is not a valid address: %w", err)
		}
	}
	if containsNewline(c.FromName) {
		return errors.New("mail: GOKAPI_MAIL_FROM_NAME contains a line break")
	}

	switch provider {
	case ProviderLog:
		return nil
	case ProviderSmtp:
		return c.validateSmtp()
	case ProviderAzure:
		return c.validateAzure()
	default:
		// Unreachable: isKnownProvider above already rejected this.
		return fmt.Errorf("mail: unhandled provider %q", c.Provider)
	}
}

func isKnownProvider(provider string) bool {
	for _, known := range AllProviders {
		if provider == known {
			return true
		}
	}
	return false
}

func (c Config) validateSmtp() error {
	if strings.TrimSpace(c.SmtpHost) == "" {
		return errors.New("mail: GOKAPI_MAIL_SMTP_HOST is required for the smtp provider")
	}
	if c.SmtpPort < 1 || c.SmtpPort > 65535 {
		return fmt.Errorf("mail: GOKAPI_MAIL_SMTP_PORT %d is out of range", c.SmtpPort)
	}
	// Credentials must never cross a link an attacker can read. This check is
	// outside the encryption switch on purpose: AllowInsecure also sets
	// InsecureSkipVerify, so with starttls or tls the connection is encrypted
	// but NOT authenticated, and anyone able to intercept it can terminate the
	// TLS themselves and read the password. An earlier version only made this
	// check under ENCRYPTION=none, which left the default starttls mode able to
	// hand credentials to a machine-in-the-middle.
	if c.SmtpAllowInsecure && c.SmtpUsername != "" {
		return errors.New("mail: refusing to send SMTP credentials with GOKAPI_MAIL_SMTP_ALLOW_INSECURE=true, since the server's certificate is then not verified")
	}
	switch c.NormalisedEncryption() {
	case EncryptionStartTls, EncryptionTls:
	case EncryptionNone:
		if !c.SmtpAllowInsecure {
			return errors.New("mail: GOKAPI_MAIL_SMTP_ENCRYPTION=none also requires GOKAPI_MAIL_SMTP_ALLOW_INSECURE=true")
		}
	default:
		return fmt.Errorf("mail: GOKAPI_MAIL_SMTP_ENCRYPTION %q must be one of %s, %s, %s",
			c.SmtpEncryption, EncryptionStartTls, EncryptionTls, EncryptionNone)
	}
	if c.SmtpUsername != "" && c.SmtpPassword == "" {
		return errors.New("mail: GOKAPI_MAIL_SMTP_USERNAME is set but GOKAPI_MAIL_SMTP_PASSWORD is empty")
	}
	return nil
}

func (c Config) validateAzure() error {
	_, _, err := c.azureCredentials()
	return err
}

// azureCredentials resolves the endpoint and access key from either the
// connection string or the two discrete variables. The connection string wins
// when both are present, because it is the value copied verbatim from the
// portal and is therefore the one least likely to have been mistyped.
func (c Config) azureCredentials() (string, string, error) {
	if strings.TrimSpace(c.AzureConnectionString) != "" {
		return parseAzureConnectionString(c.AzureConnectionString)
	}
	endpoint := strings.TrimSpace(c.AzureEndpoint)
	key := strings.TrimSpace(c.AzureAccessKey)
	if endpoint == "" || key == "" {
		return "", "", errors.New("mail: the azure provider needs GOKAPI_MAIL_AZURE_CONNECTION_STRING, or both GOKAPI_MAIL_AZURE_ENDPOINT and GOKAPI_MAIL_AZURE_ACCESS_KEY")
	}
	return normaliseAzureEndpoint(endpoint), key, nil
}

// parseAzureConnectionString reads the portal's connection string. The format
// is a semicolon-separated list of key=value pairs; the access key is base64
// and itself contains '=' padding, so each pair is split on the first '='
// only.
func parseAzureConnectionString(connectionString string) (string, string, error) {
	var endpoint, key string
	for _, part := range strings.Split(connectionString, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, found := strings.Cut(part, "=")
		if !found {
			return "", "", fmt.Errorf("mail: malformed segment %q in the Azure connection string", part)
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "endpoint":
			endpoint = strings.TrimSpace(value)
		case "accesskey":
			key = strings.TrimSpace(value)
		}
	}
	if endpoint == "" {
		return "", "", errors.New("mail: the Azure connection string has no endpoint= segment")
	}
	if key == "" {
		return "", "", errors.New("mail: the Azure connection string has no accesskey= segment")
	}
	return normaliseAzureEndpoint(endpoint), key, nil
}

func normaliseAzureEndpoint(endpoint string) string {
	return strings.TrimRight(strings.TrimSpace(endpoint), "/")
}

// Redacted returns the configuration with every secret replaced, so it can be
// logged. This mirrors the DSN redaction already applied to database
// connection strings.
func (c Config) Redacted() string {
	redact := func(value string) string {
		if value == "" {
			return ""
		}
		return "[redacted]"
	}
	// Report the endpoint actually resolved, so an operator who supplied a
	// connection string still sees which resource is being used. The key is
	// redacted whichever way it was supplied.
	azureEndpoint, azureKey := "", ""
	if c.NormalisedProvider() == ProviderAzure {
		if resolvedEndpoint, resolvedKey, err := c.azureCredentials(); err == nil {
			azureEndpoint, azureKey = resolvedEndpoint, redact(resolvedKey)
		}
	}
	return fmt.Sprintf("provider=%s from=%s smtpHost=%s smtpPort=%d smtpUser=%s smtpPass=%s smtpEncryption=%s azureEndpoint=%s azureKey=%s",
		c.NormalisedProvider(), c.FromAddress, c.SmtpHost, c.SmtpPort,
		redact(c.SmtpUsername), redact(c.SmtpPassword), c.NormalisedEncryption(),
		azureEndpoint, azureKey)
}
