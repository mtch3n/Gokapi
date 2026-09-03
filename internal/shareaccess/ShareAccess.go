// Package shareaccess is the service layer for sharing a resource with named
// email recipients.
//
// It owns the whole lifecycle: resolving an email list to recipients, issuing
// the access links, mailing them, resending a lost one, and validating a link
// on the way back in. Putting all of that behind one package is what lets the
// "no mail connector means no email sharing" rule be structural: every path
// that creates a grant goes through GrantAccess, and GrantAccess refuses.
package shareaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	gokapimail "github.com/forceu/gokapi/internal/mail"
	"github.com/forceu/gokapi/internal/models"
)

// tokenLength is the number of characters in a raw access token. At the
// alphabet used by helper.GenerateRandomString this is far beyond guessing
// range, which matters because the token alone grants access.
const tokenLength = 48

var (
	// ErrMailNotConfigured is returned when email sharing is attempted with no
	// mail connector. Creating the grants anyway would produce a share that
	// nobody can ever open, because the access link would have no way out.
	ErrMailNotConfigured = errors.New("shareaccess: sharing by email needs a mail connector, see GOKAPI_MAIL_PROVIDER")
	// ErrNoRecipients is returned when the email list is empty.
	ErrNoRecipients = errors.New("shareaccess: no recipients given")
	// ErrCooldown is returned when a link was reissued too recently.
	ErrCooldown = errors.New("shareaccess: a link was sent recently, please wait before requesting another")
	// ErrInvalidToken covers every reason a token does not grant access:
	// unknown, revoked, expired, no matching grant, or a blocked recipient.
	// The reasons are deliberately not distinguished to a caller that will
	// render them, so a probe cannot learn which files exist or who was sent
	// one.
	ErrInvalidToken = errors.New("shareaccess: this link is not valid")
	// ErrDownloadsExhausted is returned when the recipient has used their
	// whole allowance. Unlike the above it is safe to show, because the holder
	// of the link has already proved they are the recipient.
	ErrDownloadsExhausted = errors.New("shareaccess: no downloads remaining for this recipient")
)

// hashToken reduces a raw token to what is stored. Only this value ever
// reaches the database, so a disclosure of the database cannot be replayed
// into a working link.
func hashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// Resource names what is being shared, so callers pass one value rather than
// a type and an ID that could drift apart.
type Resource struct {
	Type int
	Id   string
	// Name is shown in the email so the recipient knows what is waiting.
	Name string
	// ExpiresAt is the resource's own expiry. The access link is given the
	// same lifetime, so a link can never outlive what it points at. Zero means
	// the resource does not expire, in which case the link is capped.
	ExpiresAt int64
}

// linkExpiry returns when an access link for this resource should stop
// working.
func (r Resource) linkExpiry(now time.Time) int64 {
	capped := now.Add(models.ShareLinkMaxValiditySeconds * time.Second).Unix()
	if r.ExpiresAt <= 0 || r.ExpiresAt > capped {
		return capped
	}
	return r.ExpiresAt
}

// GrantResult reports what GrantAccess did for one address.
type GrantResult struct {
	Email string
	// IsNewRecipient is true when the address had never been shared with
	// before, which the interface uses to tell the uploader that a new
	// external contact now exists.
	IsNewRecipient bool
	// MailErr is non-nil when the grant was created but the link could not be
	// delivered. The grant is deliberately kept: the uploader can resend
	// rather than having to rebuild the whole share.
	MailErr error
}

// GrantAccess shares a resource with a list of email addresses.
//
// It replaces the whole recipient list, so removing an address from the list
// revokes it. Every recipient is mailed their own access link.
//
// It refuses outright when no mail connector is configured. That check is here,
// at the single entry point for creating grants, rather than in the HTTP
// handler, so a future second caller cannot forget it.
func GrantAccess(resource Resource, emails []string, actor models.User, downloadsAllowed int, baseUrl string) ([]GrantResult, error) {
	if !gokapimail.IsEnabled() {
		return nil, ErrMailNotConfigured
	}
	if !models.IsValidShareResourceType(resource.Type) || resource.Id == "" {
		return nil, errors.New("shareaccess: invalid resource")
	}

	normalised, err := normaliseEmails(emails)
	if err != nil {
		return nil, err
	}
	if len(normalised) == 0 {
		return nil, ErrNoRecipients
	}

	now := time.Now()
	recipientIds := make([]int, 0, len(normalised))
	results := make([]GrantResult, 0, len(normalised))
	recipients := make([]models.ShareRecipient, 0, len(normalised))

	for _, email := range normalised {
		recipient, existed := database.GetShareRecipientByEmail(email)
		if !existed {
			recipient = models.ShareRecipient{Email: email, CreatedAt: now.Unix()}
			recipient.Id = database.SaveShareRecipient(recipient)
			logging.LogShareRecipientCreated(recipient, actor)
		}
		recipientIds = append(recipientIds, recipient.Id)
		recipients = append(recipients, recipient)
		results = append(results, GrantResult{Email: email, IsNewRecipient: !existed})
	}

	// Grants are written before any mail goes out. A link that arrives before
	// its grant exists would be refused, which is the one ordering that
	// produces a support call; the reverse merely means a resend is needed.
	database.SetShareGrants(resource.Type, resource.Id, recipientIds, actor.Id,
		resolveDownloadsAllowed(resource, downloadsAllowed))

	for i, recipient := range recipients {
		if err := issueAndSend(resource, recipient, baseUrl, "", now, actor, "grant"); err != nil {
			results[i].MailErr = err
		}
	}
	return results, nil
}

// resolveDownloadsAllowed returns the per-recipient budget a grant on this resource is written
// with. A caller that names a number of its own is narrowing the share and is honoured; a caller
// that names none - which is every caller today, because there is no control for it - gets the
// resource's own current limit.
//
// That is what makes the owner's one number mean what they meant by it: a file limited to three
// downloads and shared with three people gives each of them three, nine in total. Resolving it
// here, at the single entry point that creates grants, is deliberate. Storing the resolved value
// rather than reading the resource's limit back at download time is also deliberate: the grant
// row is the record of what this recipient was given, and it has to say so on its own.
//
// A resource that is itself unlimited yields an unlimited grant, and so does a file request,
// which has no download allowance to inherit.
func resolveDownloadsAllowed(resource Resource, requested int) int {
	if requested > 0 {
		return requested
	}
	switch resource.Type {
	case models.ShareResourceFile:
		file, ok := database.GetMetaDataById(resource.Id)
		if !ok || file.UnlimitedDownloads {
			return 0
		}
		return file.DownloadsRemaining
	case models.ShareResourceBundle:
		bundle, ok := database.GetFileBundle(resource.Id)
		if !ok || bundle.UnlimitedDownloads {
			return 0
		}
		return bundle.DownloadsRemaining
	default:
		return 0
	}
}

// ResendLink issues a replacement access link for one recipient.
//
// The previous links for this recipient and resource are retired first, so a
// resend does not leave another live credential in an older mail. A cooldown
// applies, because an unthrottled resend is a way to flood an inbox that the
// requester does not own.
func ResendLink(resource Resource, email string, baseUrl string, requestedIp string) error {
	if !gokapimail.IsEnabled() {
		return ErrMailNotConfigured
	}
	normalisedEmail := database.NormaliseRecipientEmail(email)
	recipient, ok := database.GetShareRecipientByEmail(normalisedEmail)
	// An unknown address, a blocked recipient and an address with no grant on
	// this resource are all reported identically by the caller, so that the
	// resend endpoint cannot be used to test whether a person was sent a file.
	if !ok || recipient.IsBlocked {
		return ErrInvalidToken
	}
	if !database.HasShareGrant(resource.Type, resource.Id, recipient.Id) {
		return ErrInvalidToken
	}

	now := time.Now()
	lastIssued := database.GetLastShareLoginTokenTime(recipient.Id, resource.Type, resource.Id)
	if lastIssued > 0 && now.Unix()-lastIssued < models.ShareLinkCooldownSeconds {
		return ErrCooldown
	}
	// The zero value marks this as a public resend to LogShareLinkMailed,
	// which records the requester's IP instead of a staff actor.
	return issueAndSend(resource, recipient, baseUrl, requestedIp, now, models.User{}, "resend")
}

// issueAndSend mails a new link and only then retires the previous one.
//
// The send happens before anything is written, so a failed send leaves
// whatever link the recipient already had - if any - untouched. Revoking
// first, as this used to do, would strand the recipient with no working link
// at all the moment the mail step failed.
//
// actor and purpose exist purely for the audit trail: actor is the staff
// user for a grant and the zero value for a public resend, purpose is
// "grant" or "resend". Both outcomes are logged - a caller must not swallow
// the error before this point, or a misconfigured connector, a bounced
// address or a timeout goes on leaving no server-side trace at all.
func issueAndSend(resource Resource, recipient models.ShareRecipient, baseUrl, requestedIp string,
	now time.Time, actor models.User, purpose string) error {
	rawToken := helper.GenerateRandomString(tokenLength)

	receipt, err := gokapimail.Send(context.Background(), buildMessage(resource, recipient, rawToken, baseUrl))
	logging.LogShareLinkMailed(resource.Type, resource.Id, recipient.Email, purpose, gokapimail.Get().Name(),
		receipt.MessageId, resource.linkExpiry(now), actor, requestedIp, err)
	if err != nil {
		return err
	}

	database.RevokeShareLoginTokens(recipient.Id, resource.Type, resource.Id)
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    hashToken(rawToken),
		RecipientId:  recipient.Id,
		ResourceType: resource.Type,
		ResourceId:   resource.Id,
		CreatedAt:    now.Unix(),
		ExpiresAt:    resource.linkExpiry(now),
		RequestedIp:  requestedIp,
	})

	return nil
}

// ValidateToken resolves a raw token to the recipient it belongs to, checking
// that it still grants access to this resource.
//
// The grant is re-checked here rather than trusted from the token, so that
// removing a recipient from the list, or blocking them, takes effect on the
// next request instead of waiting for the link to expire.
//
// firstUse is true when this recipient had never redeemed a link before (their
// LastLoginAt was zero), so the caller can raise share.link.redeemed exactly
// once per recipient/resource pair rather than on every visit.
func ValidateToken(rawToken string, resourceType int, resourceId string) (recipient models.ShareRecipient, firstUse bool, err error) {
	if rawToken == "" {
		return models.ShareRecipient{}, false, ErrInvalidToken
	}
	token, ok := database.GetShareLoginToken(hashToken(rawToken))
	if !ok || token.IsRevoked {
		return models.ShareRecipient{}, false, ErrInvalidToken
	}
	if token.ExpiresAt < time.Now().Unix() {
		return models.ShareRecipient{}, false, ErrInvalidToken
	}
	// A link is bound to the one resource it was issued for, so a token for a
	// file cannot be replayed against a different file or a bundle.
	if token.ResourceType != resourceType || token.ResourceId != resourceId {
		return models.ShareRecipient{}, false, ErrInvalidToken
	}
	if !database.HasShareGrant(resourceType, resourceId, token.RecipientId) {
		return models.ShareRecipient{}, false, ErrInvalidToken
	}
	recipient, ok = database.GetShareRecipient(token.RecipientId)
	if !ok || recipient.IsBlocked {
		return models.ShareRecipient{}, false, ErrInvalidToken
	}

	database.MarkShareLoginTokenUsed(token.TokenHash, time.Now().Unix())
	firstUse = recipient.LastLoginAt == 0
	if firstUse {
		recipient.LastLoginAt = time.Now().Unix()
		database.SaveShareRecipient(recipient)
	}
	return recipient, firstUse, nil
}

// ConsumeDownload records one download against the recipient's own allowance.
// It returns ErrDownloadsExhausted when nothing is left and no download window
// is open, in which case the caller must not serve the resource. leeway is how
// long a window stays open, in seconds; the caller resolves it for the resource
// being served (see storage.LeewayFor) rather than this deciding it, so there
// is one rule and only the window's length varies.
func ConsumeDownload(resourceType int, resourceId string, recipientId int, leeway int64) error {
	granted, _ := database.AcquireShareGrantDownload(resourceType, resourceId, recipientId, time.Now().Unix(), leeway)
	if granted {
		return nil
	}
	return ErrDownloadsExhausted
}

// normaliseEmails lower-cases, trims, validates and de-duplicates an address
// list. A malformed address is rejected outright rather than silently dropped,
// so an uploader who mistypes is told, instead of believing a share went to
// someone it never reached.
func normaliseEmails(emails []string) ([]string, error) {
	seen := make(map[string]bool, len(emails))
	result := make([]string, 0, len(emails))
	for _, raw := range emails {
		normalised := database.NormaliseRecipientEmail(raw)
		if normalised == "" {
			continue
		}
		if _, err := mail.ParseAddress(normalised); err != nil {
			return nil, fmt.Errorf("shareaccess: %q is not a valid email address", raw)
		}
		if seen[normalised] {
			continue
		}
		seen[normalised] = true
		result = append(result, normalised)
	}
	return result, nil
}

// buildMessage composes the notification. It carries the access link itself,
// so the recipient reaches the resource in one click with nothing to type.
func buildMessage(resource Resource, recipient models.ShareRecipient, rawToken, baseUrl string) gokapimail.Message {
	link := BuildAccessUrl(baseUrl, resource, rawToken)
	what := resource.Name
	if what == "" {
		what = "A file"
	}
	var body strings.Builder
	fmt.Fprintf(&body, "%s has been shared with you.\r\n\r\n", what)
	body.WriteString("Open it here:\r\n")
	body.WriteString(link + "\r\n\r\n")
	if resource.ExpiresAt > 0 {
		fmt.Fprintf(&body, "This expires on %s.\r\n",
			time.Unix(resource.ExpiresAt, 0).UTC().Format("2 January 2006 15:04 UTC"))
	}
	body.WriteString("The link is personal to this address. Do not forward it.\r\n")
	return gokapimail.Message{
		To: []string{recipient.Email},
		// The resource name is deliberately absent from the subject. A subject
		// line is rendered in notification popups and lock screens, and this
		// system carries health-adjacent filenames.
		Subject: "A secure file has been shared with you",
		Text:    body.String(),
	}
}

// PathPrefix returns the single-letter path segment the SPA's public routes use for a resource
// type ("s" for a file, "f" for a folder, "r" for a file request). Shared by BuildAccessUrl,
// which mails it inside the access link, and the inbox's open endpoint, which returns it in a
// same-origin URL for a caller who already holds a cookie.
func PathPrefix(resourceType int) string {
	switch resourceType {
	case models.ShareResourceBundle:
		return "f"
	case models.ShareResourceFileRequest:
		return "r"
	default:
		return "s"
	}
}

// BuildAccessUrl assembles the link mailed to a recipient.
func BuildAccessUrl(baseUrl string, resource Resource, rawToken string) string {
	// The token rides in the URL fragment, not the query string: a fragment is never sent to
	// the server, so it never reaches a reverse proxy's access log. The SPA reads it client-side
	// and forwards it as the sharetoken request header instead (see ShareGuard.recipientFor).
	return fmt.Sprintf("%s%s/%s#token=%s", ensureTrailingSlash(baseUrl), PathPrefix(resource.Type), resource.Id, url.QueryEscape(rawToken))
}

func ensureTrailingSlash(url string) string {
	if url == "" || strings.HasSuffix(url, "/") {
		return url
	}
	return url + "/"
}
