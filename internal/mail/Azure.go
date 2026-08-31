package mail

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// azureApiVersion is the Email REST API version this connector speaks.
const azureApiVersion = "2023-03-31"

// azureMaxErrorBody bounds how much of a failure response is read into an
// error message, so a misconfigured endpoint returning a large HTML error page
// cannot flood the log.
const azureMaxErrorBody = 4096

// azureSender delivers through the Azure Communication Services Email REST
// API, authenticating with the resource access key over HMAC-SHA256.
//
// The REST API is used rather than Azure's SMTP relay because the relay
// requires an Entra application registration and a composite username of the
// form <resource>.<application-id>.<tenant-id>. The connection string this
// connector takes is copied verbatim from the portal.
type azureSender struct {
	config     Config
	from       mail.Address
	endpoint   string
	accessKey  []byte
	httpClient *http.Client
}

func newAzureSender(config Config) (Sender, error) {
	from, err := config.senderAddress()
	if err != nil {
		return nil, err
	}
	endpoint, encodedKey, err := config.azureCredentials()
	if err != nil {
		return nil, err
	}
	// The portal shows the key base64 encoded and the signature is computed
	// over the decoded bytes. Decoding here turns a mistyped key into a
	// startup error rather than an opaque 401 at send time.
	accessKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("mail: the Azure access key is not valid base64: %w", err)
	}
	if len(accessKey) == 0 {
		return nil, fmt.Errorf("mail: the Azure access key is empty")
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mail: the Azure endpoint %q is not a valid URL: %w", endpoint, err)
	}
	// HTTPS is required, not merely expected. Over plain HTTP the message body,
	// which carries a recipient's access link and health-adjacent context,
	// crosses the network in the clear, and the signed Authorization header can
	// be captured and replayed within its timestamp window. A real Communication
	// Services endpoint is always HTTPS, so anything else is a misconfiguration
	// or an interception attempt.
	if !strings.EqualFold(parsedEndpoint.Scheme, "https") {
		return nil, fmt.Errorf("mail: the Azure endpoint must use https, got %q", endpoint)
	}
	if parsedEndpoint.Host == "" {
		return nil, fmt.Errorf("mail: the Azure endpoint %q has no host", endpoint)
	}
	return &azureSender{
		config:     config,
		from:       from,
		endpoint:   endpoint,
		accessKey:  accessKey,
		httpClient: &http.Client{Timeout: time.Duration(config.TimeoutSeconds) * time.Second},
	}, nil
}

func (a *azureSender) Name() string { return ProviderAzure }

// azureRequest mirrors the Email REST API request body.
type azureRequest struct {
	SenderAddress string            `json:"senderAddress"`
	Content       azureContent      `json:"content"`
	Recipients    azureRecipients   `json:"recipients"`
	Headers       map[string]string `json:"headers,omitempty"`
}

type azureContent struct {
	Subject   string `json:"subject"`
	PlainText string `json:"plainText"`
	Html      string `json:"html,omitempty"`
}

type azureRecipients struct {
	To []azureAddress `json:"to"`
}

type azureAddress struct {
	Address     string `json:"address"`
	DisplayName string `json:"displayName,omitempty"`
}

func (a *azureSender) Send(ctx context.Context, msg Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}

	recipients := make([]azureAddress, 0, len(msg.To))
	for _, recipient := range msg.To {
		// Azure's address field takes the bare mailbox. Message.Validate also
		// accepts the name-addr form ("Alice <alice@example.com>"), which would
		// otherwise be sent verbatim and rejected at delivery time.
		parsed, err := netMailParse(recipient)
		if err != nil {
			return fmt.Errorf("mail: recipient %q is not a valid address: %w", recipient, err)
		}
		recipients = append(recipients, azureAddress{Address: parsed.Address, DisplayName: parsed.Name})
	}
	body, err := json.Marshal(azureRequest{
		// Azure requires the bare address here. The display name travels in
		// the recipient objects and the headers, not in senderAddress.
		SenderAddress: a.from.Address,
		Content: azureContent{
			Subject:   msg.Subject,
			PlainText: msg.Text,
			Html:      msg.Html,
		},
		Recipients: azureRecipients{To: recipients},
		Headers:    map[string]string{"Auto-Submitted": "auto-generated"},
	})
	if err != nil {
		return fmt.Errorf("mail: cannot encode the Azure request: %w", err)
	}

	requestUrl := fmt.Sprintf("%s/emails:send?api-version=%s", a.endpoint, azureApiVersion)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestUrl, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("mail: cannot build the Azure request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := a.sign(request, body, time.Now().UTC()); err != nil {
		return err
	}

	response, err := a.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("mail: the Azure request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	// A successful send is asynchronous: the API returns 202 Accepted with an
	// Operation-Location header naming a status resource. Delivery is not
	// confirmed at this point, only acceptance. See the gap noted in the
	// package documentation.
	if response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusOK {
		return nil
	}
	detail, _ := io.ReadAll(io.LimitReader(response.Body, azureMaxErrorBody))
	return fmt.Errorf("mail: Azure rejected the message with status %s: %s",
		response.Status, strings.TrimSpace(string(detail)))
}

// sign applies the HMAC-SHA256 scheme the Azure Communication Services data
// plane expects. The string to sign is the verb, the path with its query, and
// the three signed header values joined by semicolons, each on its own line.
func (a *azureSender) sign(request *http.Request, body []byte, now time.Time) error {
	contentHash := sha256.Sum256(body)
	encodedHash := base64.StdEncoding.EncodeToString(contentHash[:])
	// Azure expects the RFC 1123 form with a literal GMT zone. time.RFC1123
	// renders whatever zone the value carries, so the value must be in UTC
	// and the zone name replaced.
	dateHeader := now.UTC().Format(http.TimeFormat)

	pathAndQuery := request.URL.EscapedPath()
	if request.URL.RawQuery != "" {
		pathAndQuery += "?" + request.URL.RawQuery
	}

	stringToSign := strings.Join([]string{
		request.Method,
		pathAndQuery,
		fmt.Sprintf("%s;%s;%s", dateHeader, request.URL.Host, encodedHash),
	}, "\n")

	mac := hmac.New(sha256.New, a.accessKey)
	if _, err := mac.Write([]byte(stringToSign)); err != nil {
		return fmt.Errorf("mail: cannot compute the Azure signature: %w", err)
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	request.Header.Set("x-ms-date", dateHeader)
	request.Header.Set("x-ms-content-sha256", encodedHash)
	request.Header.Set("Authorization",
		"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+signature)
	return nil
}
