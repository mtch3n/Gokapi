//go:build test

package mail

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/test"
)

const testAccessKey = "c2VjcmV0LWtleS1mb3ItdGVzdGluZy1vbmx5LTEyMzQ1Ng=="

func validMessage() Message {
	return Message{
		To:      []string{"recipient@example.com"},
		Subject: "A file is waiting for you",
		Text:    "Sign in to collect it.",
	}
}

// ---------------------------------------------------------------------------
// Message validation
// ---------------------------------------------------------------------------

func TestMessageValidate(t *testing.T) {
	test.IsNil(t, validMessage().Validate())

	t.Run("rejects no recipient", func(t *testing.T) {
		msg := validMessage()
		msg.To = nil
		test.IsNotNil(t, msg.Validate())
	})

	t.Run("rejects an unparseable recipient", func(t *testing.T) {
		msg := validMessage()
		msg.To = []string{"not-an-address"}
		test.IsNotNil(t, msg.Validate())
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		msg := validMessage()
		msg.Subject = "   "
		test.IsNotNil(t, msg.Validate())
	})

	t.Run("rejects an empty text body", func(t *testing.T) {
		msg := validMessage()
		msg.Text = ""
		test.IsNotNil(t, msg.Validate())
	})

	// Header injection is the reason Validate exists at all. A subject or a
	// recipient carrying CR or LF could terminate the header and inject
	// further headers, or a second message, into the SMTP conversation.
	t.Run("rejects header injection in the subject", func(t *testing.T) {
		for _, injected := range []string{
			"Hello\r\nBcc: attacker@example.com",
			"Hello\nBcc: attacker@example.com",
			"Hello\rX-Injected: yes",
		} {
			msg := validMessage()
			msg.Subject = injected
			test.IsNotNilWithMessage(t, msg.Validate(), injected)
		}
	})

	t.Run("rejects header injection in a recipient", func(t *testing.T) {
		msg := validMessage()
		msg.To = []string{"a@example.com\r\nBcc: attacker@example.com"}
		test.IsNotNil(t, msg.Validate())
	})
}

// ---------------------------------------------------------------------------
// MIME rendering
// ---------------------------------------------------------------------------

func TestBuildMimePlainText(t *testing.T) {
	from := mail.Address{Name: "ExchangePoint", Address: "no-reply@example.com"}
	rendered, err := buildMime(from, validMessage(), time.Now())
	test.IsNil(t, err)

	body := string(rendered)
	for _, expected := range []string{
		`From: "ExchangePoint" <no-reply@example.com>`,
		"To: recipient@example.com",
		"Subject: A file is waiting for you",
		`Content-Type: text/plain; charset="utf-8"`,
		"Content-Transfer-Encoding: quoted-printable",
		"Auto-Submitted: auto-generated",
		"MIME-Version: 1.0",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("rendered message is missing %q\ngot:\n%s", expected, body)
		}
	}
	// The Message-ID domain should follow the sender, not be a placeholder.
	if !strings.Contains(body, "@example.com>") {
		t.Errorf("Message-ID does not use the sender domain\ngot:\n%s", body)
	}
}

func TestBuildMimeMultipart(t *testing.T) {
	from := mail.Address{Address: "no-reply@example.com"}
	msg := validMessage()
	msg.Html = "<p>Sign in to collect it.</p>"

	rendered, err := buildMime(from, msg, time.Now())
	test.IsNil(t, err)
	body := string(rendered)

	if !strings.Contains(body, "multipart/alternative; boundary=") {
		t.Fatalf("expected a multipart message\ngot:\n%s", body)
	}
	// RFC 2046: a client picks the last part it understands, so the plain
	// text part has to come before the HTML part.
	plainIndex := strings.Index(body, `text/plain`)
	htmlIndex := strings.Index(body, `text/html`)
	if plainIndex == -1 || htmlIndex == -1 || plainIndex > htmlIndex {
		t.Errorf("plain text must precede HTML, got plain=%d html=%d", plainIndex, htmlIndex)
	}
}

func TestBuildMimeEncodesNonAsciiSubject(t *testing.T) {
	from := mail.Address{Address: "no-reply@example.com"}
	msg := validMessage()
	msg.Subject = "檔案已備妥"

	rendered, err := buildMime(from, msg, time.Now())
	test.IsNil(t, err)
	body := string(rendered)

	if !strings.Contains(body, "Subject: =?utf-8?q?") {
		t.Errorf("a non-ASCII subject must be RFC 2047 encoded\ngot:\n%s", body)
	}
	// The raw UTF-8 must not survive into the header.
	if strings.Contains(strings.SplitN(body, "\r\n\r\n", 2)[0], "檔案已備妥") {
		t.Errorf("raw non-ASCII leaked into the headers\ngot:\n%s", body)
	}
}

func TestBuildMimeRejectsInvalidMessage(t *testing.T) {
	from := mail.Address{Address: "no-reply@example.com"}
	_, err := buildMime(from, Message{}, time.Now())
	test.IsNotNil(t, err)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestConfigValidate(t *testing.T) {
	t.Run("disabled needs nothing", func(t *testing.T) {
		test.IsNil(t, Config{Provider: "disabled"}.Validate())
		test.IsNil(t, Config{}.Validate())
	})

	// A typo in the provider must name itself. Validating the shared settings
	// first would blame a missing GOKAPI_MAIL_FROM for an unrecognised provider
	// and send the operator looking in the wrong place.
	t.Run("an unknown provider is an error, not a silent fallback", func(t *testing.T) {
		err := Config{Provider: "sendgrid", TimeoutSeconds: 20, FromAddress: "a@b.com"}.Validate()
		test.IsNotNil(t, err)
		if !strings.Contains(err.Error(), "unknown provider") {
			t.Errorf("expected the error to name the provider, got: %v", err)
		}
	})

	t.Run("an unknown provider outranks every other complaint", func(t *testing.T) {
		err := Config{Provider: "sendgrid"}.Validate()
		test.IsNotNil(t, err)
		if !strings.Contains(err.Error(), "unknown provider") {
			t.Errorf("expected \"unknown provider\" rather than a complaint about a missing setting, got: %v", err)
		}
	})

	t.Run("smtp requires a host", func(t *testing.T) {
		config := Config{Provider: "smtp", FromAddress: "a@b.com", SmtpPort: 587, TimeoutSeconds: 20}
		test.IsNotNil(t, config.Validate())
		config.SmtpHost = "smtp.example.com"
		test.IsNil(t, config.Validate())
	})

	t.Run("a sender address is required and must parse", func(t *testing.T) {
		config := Config{Provider: "smtp", SmtpHost: "smtp.example.com", SmtpPort: 587, TimeoutSeconds: 20}
		test.IsNotNil(t, config.Validate())
		config.FromAddress = "not an address"
		test.IsNotNil(t, config.Validate())
		config.FromAddress = "a@b.com"
		test.IsNil(t, config.Validate())
	})

	t.Run("unencrypted transport must be opted into", func(t *testing.T) {
		config := Config{Provider: "smtp", FromAddress: "a@b.com", SmtpHost: "localhost",
			SmtpPort: 1025, SmtpEncryption: "none", TimeoutSeconds: 20}
		test.IsNotNil(t, config.Validate())
		config.SmtpAllowInsecure = true
		test.IsNil(t, config.Validate())
	})

	// Credentials over an unencrypted link would be sent in the clear.
	t.Run("refuses credentials over an unencrypted link", func(t *testing.T) {
		config := Config{Provider: "smtp", FromAddress: "a@b.com", SmtpHost: "localhost",
			SmtpPort: 1025, SmtpEncryption: "none", SmtpAllowInsecure: true,
			SmtpUsername: "user", SmtpPassword: "pw", TimeoutSeconds: 20}
		test.IsNotNil(t, config.Validate())
	})

	// AllowInsecure also sets InsecureSkipVerify, so with starttls or tls the
	// connection is encrypted but the peer is NOT authenticated: anyone able to
	// intercept can terminate the TLS and read the password. Refusing only
	// under ENCRYPTION=none, as an earlier version did, left the DEFAULT mode
	// able to hand credentials to a machine-in-the-middle.
	t.Run("refuses credentials whenever the certificate is unverified", func(t *testing.T) {
		for _, encryption := range []string{EncryptionStartTls, EncryptionTls, ""} {
			config := Config{Provider: "smtp", FromAddress: "a@b.com",
				SmtpHost: "smtp.example.com", SmtpPort: 587, SmtpEncryption: encryption,
				SmtpAllowInsecure: true, SmtpUsername: "user", SmtpPassword: "pw",
				TimeoutSeconds: 20}
			err := config.Validate()
			test.IsNotNilWithMessage(t, err, "encryption="+encryption)
		}
		// Without AllowInsecure the certificate is verified, so credentials
		// over starttls are fine.
		config := Config{Provider: "smtp", FromAddress: "a@b.com",
			SmtpHost: "smtp.example.com", SmtpPort: 587, SmtpEncryption: EncryptionStartTls,
			SmtpUsername: "user", SmtpPassword: "pw", TimeoutSeconds: 20}
		test.IsNil(t, config.Validate())
	})

	t.Run("a username without a password is an error", func(t *testing.T) {
		config := Config{Provider: "smtp", FromAddress: "a@b.com", SmtpHost: "smtp.example.com",
			SmtpPort: 587, SmtpUsername: "user", TimeoutSeconds: 20}
		test.IsNotNil(t, config.Validate())
	})

	t.Run("azure needs a connection string or both discrete values", func(t *testing.T) {
		config := Config{Provider: "azure", FromAddress: "a@b.com", TimeoutSeconds: 20}
		test.IsNotNil(t, config.Validate())
		config.AzureEndpoint = "https://x.communication.azure.com"
		test.IsNotNil(t, config.Validate())
		config.AzureAccessKey = testAccessKey
		test.IsNil(t, config.Validate())
	})
}

func TestParseAzureConnectionString(t *testing.T) {
	// The access key is base64 and carries '=' padding, so splitting each
	// segment on every '=' rather than the first would truncate it.
	endpoint, key, err := parseAzureConnectionString(
		"endpoint=https://demo.communication.azure.com/;accesskey=" + testAccessKey)
	test.IsNil(t, err)
	test.IsEqualString(t, endpoint, "https://demo.communication.azure.com")
	test.IsEqualString(t, key, testAccessKey)

	t.Run("is case insensitive on the key names", func(t *testing.T) {
		endpoint, key, err := parseAzureConnectionString(
			"Endpoint=https://demo.communication.azure.com/;AccessKey=" + testAccessKey)
		test.IsNil(t, err)
		test.IsEqualString(t, endpoint, "https://demo.communication.azure.com")
		test.IsEqualString(t, key, testAccessKey)
	})

	t.Run("reports a missing segment", func(t *testing.T) {
		_, _, err := parseAzureConnectionString("endpoint=https://demo.communication.azure.com/")
		test.IsNotNil(t, err)
		_, _, err = parseAzureConnectionString("accesskey=" + testAccessKey)
		test.IsNotNil(t, err)
	})
}

// An operator who supplied a connection string still needs to see which Azure
// resource is in use, so the resolved endpoint is reported while the key is not.
func TestConfigRedactedShowsResolvedAzureEndpoint(t *testing.T) {
	config := Config{
		Provider:    ProviderAzure,
		FromAddress: "a@b.com",
		AzureConnectionString: "endpoint=https://demo.communication.azure.com/;accesskey=" +
			testAccessKey,
	}
	redacted := config.Redacted()
	if !strings.Contains(redacted, "azureEndpoint=https://demo.communication.azure.com") {
		t.Errorf("the resolved endpoint must be shown, got: %s", redacted)
	}
	if strings.Contains(redacted, testAccessKey) {
		t.Errorf("the access key leaked: %s", redacted)
	}
}

func TestConfigRedactedHidesSecrets(t *testing.T) {
	config := Config{
		Provider: "smtp", FromAddress: "a@b.com", SmtpHost: "smtp.example.com",
		SmtpUsername: "the-user", SmtpPassword: "the-password",
		AzureAccessKey: testAccessKey,
	}
	redacted := config.Redacted()
	for _, secret := range []string{"the-password", testAccessKey, "the-user"} {
		if strings.Contains(redacted, secret) {
			t.Errorf("Redacted() leaked %q: %s", secret, redacted)
		}
	}
}

// ---------------------------------------------------------------------------
// Factory and the disabled connector
// ---------------------------------------------------------------------------

func TestNewSelectsConnector(t *testing.T) {
	for provider, expected := range map[string]string{
		"":         ProviderDisabled,
		"disabled": ProviderDisabled,
		"log":      ProviderLog,
		"LOG":      ProviderLog,
		"  smtp  ": ProviderSmtp,
	} {
		config := Config{Provider: provider, FromAddress: "a@b.com",
			SmtpHost: "smtp.example.com", SmtpPort: 587, TimeoutSeconds: 20}
		sender, err := New(config)
		test.IsNilWithMessage(t, err, provider)
		test.IsEqualString(t, sender.Name(), expected)
	}
}

// A disabled connector must report the misconfiguration rather than silently
// succeeding, or a user would be told a notification was sent that never was.
func TestDisabledSenderReportsNotConfigured(t *testing.T) {
	sender, err := New(Config{})
	test.IsNil(t, err)
	test.IsEqual(t, sender.Send(context.Background(), validMessage()), ErrNotConfigured)
}

func TestGetIsSafeBeforeInit(t *testing.T) {
	ResetForTesting()
	test.IsEqualString(t, Get().Name(), ProviderDisabled)
	test.IsEqualBool(t, IsEnabled(), false)
	test.IsEqual(t, Send(context.Background(), validMessage()), ErrNotConfigured)
	test.IsEqual(t, SendTest(context.Background(), "a@b.com"), ErrNotConfigured)
}

func TestInitWithConfig(t *testing.T) {
	ResetForTesting()
	defer ResetForTesting()

	test.IsNil(t, InitWithConfig(Config{Provider: ProviderLog, TimeoutSeconds: 20}))
	test.IsEqualString(t, Get().Name(), ProviderLog)
	test.IsEqualBool(t, IsEnabled(), true)
	test.IsNil(t, Send(context.Background(), validMessage()))

	t.Run("a bad configuration leaves the previous sender in place", func(t *testing.T) {
		test.IsNotNil(t, InitWithConfig(Config{Provider: "nonsense", TimeoutSeconds: 20}))
		test.IsEqualString(t, Get().Name(), ProviderLog)
	})
}

// ---------------------------------------------------------------------------
// Azure connector
// ---------------------------------------------------------------------------

func TestAzureSendSignsAndPostsCorrectly(t *testing.T) {
	type captured struct {
		method        string
		path          string
		query         string
		authorization string
		date          string
		contentHash   string
		body          []byte
		host          string
	}
	var got captured

	// A TLS server, because the connector refuses a non-https endpoint: over
	// plain HTTP the body and the signed header would be interceptable.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = captured{
			method: r.Method, path: r.URL.Path, query: r.URL.RawQuery,
			authorization: r.Header.Get("Authorization"),
			date:          r.Header.Get("x-ms-date"),
			contentHash:   r.Header.Get("x-ms-content-sha256"),
			body:          body, host: r.Host,
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sender, err := New(Config{
		Provider: ProviderAzure, FromAddress: "no-reply@example.com", FromName: "ExchangePoint",
		AzureEndpoint: server.URL, AzureAccessKey: testAccessKey, TimeoutSeconds: 20,
	})
	test.IsNil(t, err)
	sender.(*azureSender).httpClient = server.Client()

	msg := validMessage()
	msg.Html = "<p>Sign in.</p>"
	test.IsNil(t, sender.Send(context.Background(), msg))

	test.IsEqualString(t, got.method, http.MethodPost)
	test.IsEqualString(t, got.path, "/emails:send")
	test.IsEqualString(t, got.query, "api-version="+azureApiVersion)

	t.Run("the body matches the Email REST schema", func(t *testing.T) {
		var request azureRequest
		test.IsNil(t, json.Unmarshal(got.body, &request))
		// senderAddress must be the bare address: Azure rejects a display name here.
		test.IsEqualString(t, request.SenderAddress, "no-reply@example.com")
		test.IsEqualString(t, request.Content.Subject, msg.Subject)
		test.IsEqualString(t, request.Content.PlainText, msg.Text)
		test.IsEqualString(t, request.Content.Html, msg.Html)
		test.IsEqualInt(t, len(request.Recipients.To), 1)
		test.IsEqualString(t, request.Recipients.To[0].Address, "recipient@example.com")
	})

	t.Run("the content hash covers the exact body", func(t *testing.T) {
		sum := sha256.Sum256(got.body)
		test.IsEqualString(t, got.contentHash, base64.StdEncoding.EncodeToString(sum[:]))
	})

	// Recompute the signature independently. This is what catches a change to
	// the string-to-sign layout, which would otherwise only show up as a 401
	// against the real service.
	t.Run("the signature is recomputable", func(t *testing.T) {
		stringToSign := strings.Join([]string{
			"POST",
			"/emails:send?api-version=" + azureApiVersion,
			got.date + ";" + got.host + ";" + got.contentHash,
		}, "\n")
		key, err := base64.StdEncoding.DecodeString(testAccessKey)
		test.IsNil(t, err)
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(stringToSign))
		expected := "HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=" +
			base64.StdEncoding.EncodeToString(mac.Sum(nil))
		test.IsEqualString(t, got.authorization, expected)
	})

	t.Run("the date header is RFC 1123 in GMT", func(t *testing.T) {
		parsed, err := time.Parse(http.TimeFormat, got.date)
		test.IsNil(t, err)
		if !strings.HasSuffix(got.date, "GMT") {
			t.Errorf("x-ms-date must end in GMT, got %q", got.date)
		}
		if time.Since(parsed) > time.Minute {
			t.Errorf("x-ms-date is stale: %q", got.date)
		}
	})
}

func TestAzureSendReportsServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"Unauthorized","message":"bad signature"}}`))
	}))
	defer server.Close()

	sender, err := New(Config{
		Provider: ProviderAzure, FromAddress: "no-reply@example.com",
		AzureEndpoint: server.URL, AzureAccessKey: testAccessKey, TimeoutSeconds: 20,
	})
	test.IsNil(t, err)
	sender.(*azureSender).httpClient = server.Client()

	err = sender.Send(context.Background(), validMessage())
	test.IsNotNil(t, err)
	if !strings.Contains(err.Error(), "bad signature") {
		t.Errorf("the server's explanation must survive into the error, got: %v", err)
	}
}

// Over plain HTTP the body, which carries a recipient's access link, crosses
// the network in the clear and the signed Authorization header can be replayed.
// A real Communication Services endpoint is always HTTPS.
func TestAzureRequiresHttps(t *testing.T) {
	for _, endpoint := range []string{
		"http://demo.communication.azure.com",
		"http://127.0.0.1:8080",
		"ftp://demo.communication.azure.com",
	} {
		_, err := New(Config{Provider: ProviderAzure, FromAddress: "a@b.com", TimeoutSeconds: 20,
			AzureEndpoint: endpoint, AzureAccessKey: testAccessKey})
		test.IsNotNilWithMessage(t, err, endpoint)
	}

	// The same check applies when the endpoint arrived in a connection string.
	_, err := New(Config{Provider: ProviderAzure, FromAddress: "a@b.com", TimeoutSeconds: 20,
		AzureConnectionString: "endpoint=http://demo.communication.azure.com/;accesskey=" + testAccessKey})
	test.IsNotNil(t, err)

	_, err = New(Config{Provider: ProviderAzure, FromAddress: "a@b.com", TimeoutSeconds: 20,
		AzureEndpoint: "https://demo.communication.azure.com", AzureAccessKey: testAccessKey})
	test.IsNil(t, err)
}

// Both transports put the recipient into a field that takes a bare mailbox, so
// the name-addr form has to be normalised rather than passed through.
func TestAzureNormalisesRecipientAddress(t *testing.T) {
	var captured azureRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sender, err := New(Config{Provider: ProviderAzure, FromAddress: "no-reply@example.com",
		AzureEndpoint: server.URL, AzureAccessKey: testAccessKey, TimeoutSeconds: 20})
	test.IsNil(t, err)
	azure := sender.(*azureSender)
	azure.httpClient = server.Client()

	msg := validMessage()
	msg.To = []string{"Alice Example <alice@example.com>"}
	test.IsNil(t, azure.Send(context.Background(), msg))

	test.IsEqualInt(t, len(captured.Recipients.To), 1)
	test.IsEqualString(t, captured.Recipients.To[0].Address, "alice@example.com")
	test.IsEqualString(t, captured.Recipients.To[0].DisplayName, "Alice Example")
}

// The body now carries a bearer credential, so the development connector must
// not write it where log rotation and shipping will spread it.
func TestLogConnectorDoesNotLogTheBody(t *testing.T) {
	var captured bytes.Buffer
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&captured)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	}()

	sender, err := New(Config{Provider: ProviderLog, TimeoutSeconds: 20})
	test.IsNil(t, err)

	msg := validMessage()
	// Current mailed links carry the token in a fragment (#token=), but a legacy ?token=
	// link (issued up to 30 days before the fragment form shipped) can still be in a body,
	// so both forms must be proven not to leak.
	msg.Text = "Open it here:\r\nhttps://x.test/s/abc#token=SUPER-SECRET-TOKEN\r\n" +
		"Legacy link: https://x.test/s/abc?token=LEGACY-SECRET-TOKEN\r\n"
	test.IsNil(t, sender.Send(context.Background(), msg))

	logged := captured.String()
	if strings.Contains(logged, "SUPER-SECRET-TOKEN") {
		t.Errorf("the access token reached the log: %s", logged)
	}
	if strings.Contains(logged, "LEGACY-SECRET-TOKEN") {
		t.Errorf("the legacy access token reached the log: %s", logged)
	}
	// The recipient and subject are still recorded, which is what makes the
	// connector useful for proving a flow reached the send.
	if !strings.Contains(logged, "recipient@example.com") {
		t.Errorf("the recipient should still be logged: %s", logged)
	}
}

func TestAzureRejectsBadAccessKey(t *testing.T) {
	_, err := New(Config{
		Provider: ProviderAzure, FromAddress: "a@b.com", TimeoutSeconds: 20,
		AzureEndpoint: "https://x.communication.azure.com", AzureAccessKey: "not!base64!",
	})
	test.IsNotNil(t, err)
}

func TestAzureValidatesMessageBeforeSending(t *testing.T) {
	var called bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sender, err := New(Config{
		Provider: ProviderAzure, FromAddress: "no-reply@example.com",
		AzureEndpoint: server.URL, AzureAccessKey: testAccessKey, TimeoutSeconds: 20,
	})
	test.IsNil(t, err)
	sender.(*azureSender).httpClient = server.Client()

	bad := validMessage()
	bad.Subject = "Injected\r\nBcc: attacker@example.com"
	test.IsNotNil(t, sender.Send(context.Background(), bad))
	test.IsEqualBool(t, called, false)
}
