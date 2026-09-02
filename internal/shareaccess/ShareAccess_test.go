//go:build test

package shareaccess

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/logging"
	gokapimail "github.com/forceu/gokapi/internal/mail"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(false)
	configuration.Load()
	configuration.ConnectDatabase()
	exitVal := m.Run()
	testconfiguration.Delete()
	os.Exit(exitVal)
}

func enableMail(t *testing.T) {
	t.Helper()
	test.IsNil(t, gokapimail.InitWithConfig(gokapimail.Config{
		Provider: gokapimail.ProviderLog, TimeoutSeconds: 20}))
}

func disableMail(t *testing.T) {
	t.Helper()
	gokapimail.ResetForTesting()
}

// testActor stands in for the staff user granting access, so a test can
// still assert on the id GrantAccess records without spelling out a name.
func testActor(id int) models.User {
	return models.User{Id: id, Name: fmt.Sprintf("user%d@example.com", id)}
}

func testResource(id string) Resource {
	return Resource{
		Type:      models.ShareResourceFile,
		Id:        id,
		Name:      "labs-report.pdf",
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
}

// The whole point of routing every grant through this package: with no mail
// connector there is no way to deliver an access link, so creating the grants
// would produce a share nobody can ever open. It must fail closed, and it must
// not write anything.
func TestGrantAccessRefusedWithoutMail(t *testing.T) {
	disableMail(t)
	resource := testResource("res-nomail")

	results, err := GrantAccess(resource, []string{"a@example.com"}, testActor(1), 0, "https://x.test/")
	test.IsEqual(t, err, ErrMailNotConfigured)
	test.IsEqualInt(t, len(results), 0)

	// Nothing may have been written.
	test.IsEqualBool(t, database.IsShareRestricted(resource.Type, resource.Id), false)
	_, exists := database.GetShareRecipientByEmail("a@example.com")
	test.IsEqualBool(t, exists, false)

	// The resend path is guarded too.
	test.IsEqual(t, ResendLink(resource, "a@example.com", "https://x.test/", ""), ErrMailNotConfigured)
}

func TestGrantAccessCreatesRecipientsAndGrants(t *testing.T) {
	enableMail(t)
	defer disableMail(t)
	resource := testResource("res-grant")

	results, err := GrantAccess(resource,
		[]string{"  Alice@Example.com ", "bob@example.com"}, testActor(42), 3, "https://x.test/")
	test.IsNil(t, err)
	test.IsEqualInt(t, len(results), 2)

	// Addresses are normalised, and both are new.
	test.IsEqualString(t, results[0].Email, "alice@example.com")
	test.IsEqualBool(t, results[0].IsNewRecipient, true)
	test.IsNil(t, results[0].MailErr)

	test.IsEqualBool(t, database.IsShareRestricted(resource.Type, resource.Id), true)
	grants := database.GetShareGrants(resource.Type, resource.Id)
	test.IsEqualInt(t, len(grants), 2)
	test.IsEqualInt(t, grants[0].GrantedBy, 42)
	test.IsEqualInt(t, grants[0].DownloadsAllowed, 3)

	// The mail send is audited too, once per recipient, actor is the
	// granting staff user.
	t.Run("mails a success audit entry per recipient", func(t *testing.T) {
		time.Sleep(500 * time.Millisecond)
		entries, _ := logging.GetAuditEntriesSince(0, 1000)
		found := 0
		for _, entry := range entries {
			if entry.Action != "mail.share_link" || entry.FileId != resource.Id {
				continue
			}
			found++
			test.IsEqual(t, entry.Outcome, logging.OutcomeSuccess)
			test.IsEqualInt(t, entry.Actor.UserId, 42)
			test.IsEqualBool(t, strings.Contains(entry.Detail, "purpose=grant"), true)
		}
		test.IsEqualInt(t, found, 2)
	})

	// A brand-new email address logs share.recipient.created, once per new address, with the
	// granting staff user as actor.
	t.Run("logs share.recipient.created for each new address", func(t *testing.T) {
		entries, _ := logging.GetAuditEntriesSince(0, 1000)
		found := 0
		for _, entry := range entries {
			if entry.Action != "share.recipient.created" {
				continue
			}
			if entry.Detail != "alice@example.com" && entry.Detail != "bob@example.com" {
				continue
			}
			found++
			test.IsEqualInt(t, entry.Actor.UserId, 42)
		}
		test.IsEqualInt(t, found, 2)
	})

	// Re-granting to a known address does not create a second recipient.
	results, err = GrantAccess(resource, []string{"alice@example.com"}, testActor(42), 3, "https://x.test/")
	test.IsNil(t, err)
	test.IsEqualBool(t, results[0].IsNewRecipient, false)

	// Nor does it log a second share.recipient.created for that address.
	t.Run("does not re-log share.recipient.created for a known address", func(t *testing.T) {
		entries, _ := logging.GetAuditEntriesSince(0, 1000)
		found := 0
		for _, entry := range entries {
			if entry.Action == "share.recipient.created" && entry.Detail == "alice@example.com" {
				found++
			}
		}
		test.IsEqualInt(t, found, 1)
	})

	// Replacing the list revokes the address that was dropped.
	bob, ok := database.GetShareRecipientByEmail("bob@example.com")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, database.HasShareGrant(resource.Type, resource.Id, bob.Id), false)
}

func TestGrantAccessRejectsBadInput(t *testing.T) {
	enableMail(t)
	defer disableMail(t)

	// A mistyped address is reported rather than silently dropped, so an
	// uploader is never left believing a share reached someone it did not.
	_, err := GrantAccess(testResource("res-bad"), []string{"not-an-address"}, testActor(1), 0, "https://x.test/")
	test.IsNotNil(t, err)

	_, err = GrantAccess(testResource("res-bad"), []string{"  ", ""}, testActor(1), 0, "https://x.test/")
	test.IsEqual(t, err, ErrNoRecipients)

	_, err = GrantAccess(Resource{Type: 99, Id: "x"}, []string{"a@b.com"}, testActor(1), 0, "https://x.test/")
	test.IsNotNil(t, err)
}

// A link must resolve to its recipient, be bound to one resource, and be
// re-checked against the live grant on every use.
func TestValidateToken(t *testing.T) {
	enableMail(t)
	defer disableMail(t)
	resource := testResource("res-validate")

	_, err := GrantAccess(resource, []string{"carol@example.com"}, testActor(1), 0, "https://x.test/")
	test.IsNil(t, err)
	carol, _ := database.GetShareRecipientByEmail("carol@example.com")

	rawToken := issueTokenForTest(t, resource, carol.Id)

	recipient, _, err := ValidateToken(rawToken, resource.Type, resource.Id)
	test.IsNil(t, err)
	test.IsEqualInt(t, recipient.Id, carol.Id)

	// Reusable by design: a second use still works. A single-use link would be
	// burned by a mail scanner before the human ever clicked.
	_, _, err = ValidateToken(rawToken, resource.Type, resource.Id)
	test.IsNil(t, err)

	t.Run("is bound to one resource", func(t *testing.T) {
		_, _, err := ValidateToken(rawToken, resource.Type, "another-resource")
		test.IsEqual(t, err, ErrInvalidToken)
		_, _, err = ValidateToken(rawToken, models.ShareResourceBundle, resource.Id)
		test.IsEqual(t, err, ErrInvalidToken)
	})

	t.Run("rejects unknown and empty tokens", func(t *testing.T) {
		_, _, err := ValidateToken("", resource.Type, resource.Id)
		test.IsEqual(t, err, ErrInvalidToken)
		_, _, err = ValidateToken("not-a-real-token", resource.Type, resource.Id)
		test.IsEqual(t, err, ErrInvalidToken)
	})

	// Blocking must take effect on the next request, not when the link expires.
	t.Run("refuses a blocked recipient", func(t *testing.T) {
		carol.IsBlocked = true
		database.SaveShareRecipient(carol)
		_, _, err := ValidateToken(rawToken, resource.Type, resource.Id)
		test.IsEqual(t, err, ErrInvalidToken)
		carol.IsBlocked = false
		database.SaveShareRecipient(carol)
	})

	// Removing the grant revokes immediately, without touching the token.
	t.Run("refuses once the grant is gone", func(t *testing.T) {
		database.DeleteShareGrants(resource.Type, resource.Id)
		_, _, err := ValidateToken(rawToken, resource.Type, resource.Id)
		test.IsEqual(t, err, ErrInvalidToken)
	})
}

// TestValidateTokenReportsFirstUseOnlyOnce is a regression test for Part F: a mailed link's
// first redemption must be distinguishable from every visit after it, so share.link.redeemed
// can be raised exactly once per recipient/resource pair rather than on every open.
func TestValidateTokenReportsFirstUseOnlyOnce(t *testing.T) {
	enableMail(t)
	defer disableMail(t)
	resource := testResource("res-firstuse")

	_, err := GrantAccess(resource, []string{"kim@example.com"}, testActor(1), 0, "https://x.test/")
	test.IsNil(t, err)
	kim, _ := database.GetShareRecipientByEmail("kim@example.com")
	test.IsEqualInt64(t, kim.LastLoginAt, 0)

	rawToken := issueTokenForTest(t, resource, kim.Id)

	_, firstUse, err := ValidateToken(rawToken, resource.Type, resource.Id)
	test.IsNil(t, err)
	test.IsEqualBool(t, firstUse, true)

	_, firstUse, err = ValidateToken(rawToken, resource.Type, resource.Id)
	test.IsNil(t, err)
	test.IsEqualBool(t, firstUse, false)

	// A second token for the same recipient and resource is still not a first use: firstUse
	// tracks the recipient (LastLoginAt), not the token.
	secondToken := issueTokenForTest(t, resource, kim.Id)
	_, firstUse, err = ValidateToken(secondToken, resource.Type, resource.Id)
	test.IsNil(t, err)
	test.IsEqualBool(t, firstUse, false)
}

func TestValidateTokenRejectsExpired(t *testing.T) {
	enableMail(t)
	defer disableMail(t)
	resource := testResource("res-expired")
	_, err := GrantAccess(resource, []string{"dan@example.com"}, testActor(1), 0, "https://x.test/")
	test.IsNil(t, err)
	dan, _ := database.GetShareRecipientByEmail("dan@example.com")

	rawToken := "expired-raw-token-value"
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    hashToken(rawToken),
		RecipientId:  dan.Id,
		ResourceType: resource.Type,
		ResourceId:   resource.Id,
		CreatedAt:    time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt:    time.Now().Add(-time.Hour).Unix(),
	})
	_, _, err = ValidateToken(rawToken, resource.Type, resource.Id)
	test.IsEqual(t, err, ErrInvalidToken)
}

// Reissuing must retire the previous link, or every resend leaves another live
// bearer credential in an inbox.
//
// The grant is created directly rather than through GrantAccess, because
// GrantAccess issues a link of its own and the cooldown reads the most recent
// issue time for the recipient and resource. Controlling every token here is
// what makes the cooldown assertion mean what it says.
func TestResendRetiresPreviousLinkAndThrottles(t *testing.T) {
	enableMail(t)
	defer disableMail(t)
	resource := testResource("res-resend")

	erinId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "erin@example.com", CreatedAt: time.Now().Unix()})
	database.SetShareGrants(resource.Type, resource.Id, []int{erinId}, 1, 0)

	firstToken := issueTokenForTest(t, resource, erinId)
	_, _, err := ValidateToken(firstToken, resource.Type, resource.Id)
	test.IsNil(t, err)

	// A link was just issued, so an immediate resend is throttled.
	test.IsEqual(t, ResendLink(resource, "erin@example.com", "https://x.test/", "1.2.3.4"), ErrCooldown)

	// Age the only issue past the cooldown, then resend for real.
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    hashToken(firstToken),
		RecipientId:  erinId,
		ResourceType: resource.Type,
		ResourceId:   resource.Id,
		CreatedAt:    time.Now().Add(-time.Hour).Unix(),
		ExpiresAt:    resource.ExpiresAt,
	})
	test.IsNil(t, ResendLink(resource, "erin@example.com", "https://x.test/", "1.2.3.4"))

	// The link that was in the older mail is now dead.
	_, _, err = ValidateToken(firstToken, resource.Type, resource.Id)
	test.IsEqual(t, err, ErrInvalidToken)
}

// An unknown address and a real one must be indistinguishable, or the resend
// endpoint becomes a way to test who was sent a file.
func TestResendDoesNotRevealWhoIsARecipient(t *testing.T) {
	enableMail(t)
	defer disableMail(t)
	resource := testResource("res-oracle")
	_, err := GrantAccess(resource, []string{"frank@example.com"}, testActor(1), 0, "https://x.test/")
	test.IsNil(t, err)

	unknown := ResendLink(resource, "stranger@example.com", "https://x.test/", "")
	notARecipient := ResendLink(Resource{Type: models.ShareResourceFile, Id: "other-res"},
		"frank@example.com", "https://x.test/", "")

	test.IsEqual(t, unknown, ErrInvalidToken)
	test.IsEqual(t, notARecipient, ErrInvalidToken)
}

// A failed send must never strand a recipient with no working link at all.
// issueAndSend used to revoke the previous token before attempting to mail
// the new one, so a delivery failure left the recipient holding a dead link
// with nothing to replace it.
func TestResendFailedSendDoesNotStrandRecipient(t *testing.T) {
	enableMail(t)
	defer disableMail(t)
	resource := testResource("res-failed-send")

	// Saved directly, bypassing GrantAccess's address validation, so the
	// address is malformed enough that mail.Message.Validate rejects it and
	// the log connector's Send call fails deterministically.
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "not-a-valid-address", CreatedAt: time.Now().Unix()})
	database.SetShareGrants(resource.Type, resource.Id, []int{recipientId}, 1, 0)

	// The recipient's current, working link - issued a while ago so a resend
	// is not itself refused by the cooldown.
	oldToken := "old-working-token-failed-send"
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    hashToken(oldToken),
		RecipientId:  recipientId,
		ResourceType: resource.Type,
		ResourceId:   resource.Id,
		CreatedAt:    time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt:    resource.ExpiresAt,
	})

	err := ResendLink(resource, "not-a-valid-address", "https://x.test/", "")
	test.IsNotNil(t, err)
	// Not the sentinel used for the reasons that must stay hidden from a
	// caller - this is a genuine send failure, distinguishable server-side.
	test.IsEqualBool(t, errors.Is(err, ErrInvalidToken), false)

	// The old link must still work: nothing was revoked.
	_, _, err = ValidateToken(oldToken, resource.Type, resource.Id)
	test.IsNil(t, err)

	// The failure must not vanish silently: a genuine send failure on the
	// public resend path is still audited, with the anonymous actor a resend
	// always carries.
	t.Run("mails a failure audit entry", func(t *testing.T) {
		time.Sleep(500 * time.Millisecond)
		entries, _ := logging.GetAuditEntriesSince(0, 1000)
		found := false
		for _, entry := range entries {
			if entry.Action != "mail.share_link" || entry.FileId != resource.Id {
				continue
			}
			found = true
			test.IsEqual(t, entry.Outcome, logging.OutcomeFailure)
			test.IsEqualBool(t, entry.Actor.Anonymous, true)
			test.IsEqualBool(t, entry.Error != "", true)
			test.IsEqualBool(t, strings.Contains(entry.Detail, "purpose=resend"), true)
		}
		test.IsEqualBool(t, found, true)
	})
}

func TestConsumeDownloadHonoursPerRecipientAllowance(t *testing.T) {
	enableMail(t)
	defer disableMail(t)
	resource := testResource("res-consume")
	_, err := GrantAccess(resource, []string{"gail@example.com", "hank@example.com"}, testActor(1), 2, "https://x.test/")
	test.IsNil(t, err)
	gail, _ := database.GetShareRecipientByEmail("gail@example.com")
	hank, _ := database.GetShareRecipientByEmail("hank@example.com")

	test.IsNil(t, ConsumeDownload(resource.Type, resource.Id, gail.Id))
	test.IsNil(t, ConsumeDownload(resource.Type, resource.Id, gail.Id))
	test.IsEqual(t, ConsumeDownload(resource.Type, resource.Id, gail.Id), ErrDownloadsExhausted)

	// The allowance is per recipient, so Hank still has his own.
	test.IsNil(t, ConsumeDownload(resource.Type, resource.Id, hank.Id))
}

// A link may never outlive the resource it points at.
func TestLinkExpiryFollowsResource(t *testing.T) {
	now := time.Now()
	soon := now.Add(24 * time.Hour).Unix()
	test.IsEqualInt64(t, Resource{ExpiresAt: soon}.linkExpiry(now), soon)

	// No expiry on the resource means the cap applies.
	capped := now.Add(models.ShareLinkMaxValiditySeconds * time.Second).Unix()
	test.IsEqualInt64(t, Resource{ExpiresAt: 0}.linkExpiry(now), capped)

	// A resource outliving the cap is still capped.
	far := now.Add(365 * 24 * time.Hour).Unix()
	test.IsEqualInt64(t, Resource{ExpiresAt: far}.linkExpiry(now), capped)
}

// The raw token must never be derivable from what is stored.
func TestTokenIsStoredHashedOnly(t *testing.T) {
	raw := "a-secret-token-value"
	hashed := hashToken(raw)
	test.IsNotEqualString(t, hashed, raw)
	test.IsEqualInt(t, len(hashed), 64)
	test.IsEqualString(t, hashToken(raw), hashed)
	test.IsNotEqualString(t, hashToken("a-secret-token-valuf"), hashed)
}

func TestBuildAccessUrl(t *testing.T) {
	// The token rides in the fragment, not the query string, so it never reaches a reverse
	// proxy's access log - a fragment is never sent to the server.
	test.IsEqualString(t,
		BuildAccessUrl("https://x.test", Resource{Type: models.ShareResourceFile, Id: "abc"}, "tok"),
		"https://x.test/s/abc#token=tok")
	// A base URL that already ends in a slash must not produce a double one.
	test.IsEqualString(t,
		BuildAccessUrl("https://x.test/", Resource{Type: models.ShareResourceBundle, Id: "abc"}, "tok"),
		"https://x.test/f/abc#token=tok")
	test.IsEqualString(t,
		BuildAccessUrl("https://x.test/", Resource{Type: models.ShareResourceFileRequest, Id: "abc"}, "tok"),
		"https://x.test/r/abc#token=tok")
}

// The subject must not carry the filename: it is rendered on lock screens and
// in notification popups, and this system carries health-adjacent names.
func TestMailSubjectDoesNotLeakFilename(t *testing.T) {
	msg := buildMessage(testResource("res-subject"),
		models.ShareRecipient{Email: "a@example.com"}, "tok", "https://x.test/")
	test.IsEqualBool(t, msg.Subject == "A secure file has been shared with you", true)
	if contains(msg.Subject, "labs-report.pdf") {
		t.Errorf("the filename leaked into the subject: %q", msg.Subject)
	}
	// The body does carry the link, which is the whole point.
	if !contains(msg.Text, "https://x.test/s/res-subject#token=tok") {
		t.Errorf("the access link is missing from the body:\n%s", msg.Text)
	}
	test.IsNil(t, msg.Validate())
}

// ---------------------------------------------------------------------------
// Cookie exchange
// ---------------------------------------------------------------------------

func TestCookieRoundTrip(t *testing.T) {
	resetCookieStoreForTesting()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://x.test/s/res-cookie", nil)

	WriteCookie(recorder, request, models.ShareResourceFile, "res-cookie", 99)

	cookies := recorder.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	cookie := cookies[0]
	test.IsEqualString(t, cookie.Name, CookieName(models.ShareResourceFile, "res-cookie"))
	test.IsEqualBool(t, cookie.HttpOnly, true)

	// The cookie value must not be the recipient ID or anything guessable.
	test.IsEqualInt(t, len(cookie.Value), cookieLength)

	next := httptest.NewRequest(http.MethodGet, "https://x.test/downloadFile", nil)
	next.AddCookie(cookie)
	recipientId, ok := ReadCookie(next, models.ShareResourceFile, "res-cookie")
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, recipientId, 99)

	t.Run("is bound to its resource", func(t *testing.T) {
		other := httptest.NewRequest(http.MethodGet, "https://x.test/", nil)
		other.AddCookie(&http.Cookie{
			Name:  CookieName(models.ShareResourceFile, "different-res"),
			Value: cookie.Value,
		})
		_, ok := ReadCookie(other, models.ShareResourceFile, "different-res")
		test.IsEqualBool(t, ok, false)
	})

	t.Run("a request with no cookie is refused", func(t *testing.T) {
		bare := httptest.NewRequest(http.MethodGet, "https://x.test/", nil)
		_, ok := ReadCookie(bare, models.ShareResourceFile, "res-cookie")
		test.IsEqualBool(t, ok, false)
	})
}

func TestCookieExpires(t *testing.T) {
	resetCookieStoreForTesting()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://x.test/", nil)
	WriteCookie(recorder, request, models.ShareResourceFile, "res-expiry", 7)
	cookie := recorder.Result().Cookies()[0]

	// Age it past its expiry.
	cookieMutex.Lock()
	entry := cookieStore[cookie.Value]
	entry.Expiry = time.Now().Add(-time.Minute).Unix()
	cookieStore[cookie.Value] = entry
	cookieMutex.Unlock()

	next := httptest.NewRequest(http.MethodGet, "https://x.test/", nil)
	next.AddCookie(cookie)
	_, ok := ReadCookie(next, models.ShareResourceFile, "res-expiry")
	test.IsEqualBool(t, ok, false)
}

// Secure must follow how the request actually arrived, including behind a
// terminating proxy, or the flag is either always wrong in development or
// always missing in production.
func TestCookieSecureFlagFollowsScheme(t *testing.T) {
	resetCookieStoreForTesting()

	plain := httptest.NewRequest(http.MethodGet, "http://x.test/", nil)
	recorder := httptest.NewRecorder()
	WriteCookie(recorder, plain, models.ShareResourceFile, "res-plain", 1)
	test.IsEqualBool(t, recorder.Result().Cookies()[0].Secure, false)

	proxied := httptest.NewRequest(http.MethodGet, "http://x.test/", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")
	recorder = httptest.NewRecorder()
	WriteCookie(recorder, proxied, models.ShareResourceFile, "res-proxied", 1)
	test.IsEqualBool(t, recorder.Result().Cookies()[0].Secure, true)
}

func TestCookieNameIsPerResourceType(t *testing.T) {
	// A file and a bundle sharing an ID must not share a cookie.
	test.IsNotEqualString(t,
		CookieName(models.ShareResourceFile, "same"),
		CookieName(models.ShareResourceBundle, "same"))
	test.IsNotEqualString(t,
		CookieName(models.ShareResourceFileRequest, "same"),
		CookieName(models.ShareResourceBundle, "same"))
}

// ---------------------------------------------------------------------------

// issueTokenForTest stores a link directly, returning the raw token. The
// production path mails the token rather than returning it, so a test needs
// its own way to obtain one.
func issueTokenForTest(t *testing.T, resource Resource, recipientId int) string {
	t.Helper()
	raw := "raw-token-" + resource.Id + "-" + time.Now().Format("150405.000000000")
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    hashToken(raw),
		RecipientId:  recipientId,
		ResourceType: resource.Type,
		ResourceId:   resource.Id,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    resource.linkExpiry(time.Now()),
	})
	return raw
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// The whole feature rests on this: a resource with a recipient list must not be
// reachable without a valid grant, and the allowance must be spent per
// recipient rather than from one shared pool.
func TestAccessGateEndToEnd(t *testing.T) {
	enableMail(t)
	defer disableMail(t)
	resetCookieStoreForTesting()
	resource := testResource("res-gate")

	_, err := GrantAccess(resource, []string{"ivy@example.com", "jack@example.com"}, testActor(1), 2, "https://x.test/")
	test.IsNil(t, err)
	ivy, _ := database.GetShareRecipientByEmail("ivy@example.com")
	jack, _ := database.GetShareRecipientByEmail("jack@example.com")

	// The resource now reads as identity-restricted, which is what the
	// download path keys off.
	test.IsEqualBool(t, database.IsShareRestricted(resource.Type, resource.Id), true)

	// A stranger holding the link but no token gets nothing.
	_, _, err = ValidateToken("some-token-a-stranger-guessed", resource.Type, resource.Id)
	test.IsEqual(t, err, ErrInvalidToken)

	// A real recipient's token resolves, and exchanges for a cookie so the
	// token stops riding in later URLs.
	ivyToken := issueTokenForTest(t, resource, ivy.Id)
	recipient, _, err := ValidateToken(ivyToken, resource.Type, resource.Id)
	test.IsNil(t, err)
	test.IsEqualInt(t, recipient.Id, ivy.Id)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://x.test/s/res-gate?token="+ivyToken, nil)
	WriteCookie(recorder, request, resource.Type, resource.Id, ivy.Id)
	cookie := recorder.Result().Cookies()[0]

	next := httptest.NewRequest(http.MethodGet, "https://x.test/downloadFile?id=res-gate", nil)
	next.AddCookie(cookie)
	fromCookie, ok := ReadCookie(next, resource.Type, resource.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, fromCookie, ivy.Id)

	// Ivy spends her own allowance and no one else's.
	test.IsNil(t, ConsumeDownload(resource.Type, resource.Id, ivy.Id))
	test.IsNil(t, ConsumeDownload(resource.Type, resource.Id, ivy.Id))
	test.IsEqual(t, ConsumeDownload(resource.Type, resource.Id, ivy.Id), ErrDownloadsExhausted)
	test.IsNil(t, ConsumeDownload(resource.Type, resource.Id, jack.Id))

	// Revoking Ivy takes effect at once, without waiting for her link or her
	// cookie to expire.
	GrantAccess(resource, []string{"jack@example.com"}, testActor(1), 2, "https://x.test/")
	_, _, err = ValidateToken(ivyToken, resource.Type, resource.Id)
	test.IsEqual(t, err, ErrInvalidToken)
	test.IsEqualBool(t, database.HasShareGrant(resource.Type, resource.Id, ivy.Id), false)

	// Clearing the list returns the resource to an anonymous access mode.
	database.DeleteShareGrants(resource.Type, resource.Id)
	test.IsEqualBool(t, database.IsShareRestricted(resource.Type, resource.Id), false)
}
