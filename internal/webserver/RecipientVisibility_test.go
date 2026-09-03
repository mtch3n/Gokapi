//go:build !integration && test

package webserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/webserver/ratelimiter"
)

// A recipient who has spent their own allowance is finished with the file. They are no longer
// entitled to its name, its size or even its existence, however much budget the other recipients
// still have - so /pubapi/file answers them exactly as it answers a caller holding an id that was
// never real. Before this it answered them with a 200 and the whole record, because the
// authorisation here was a membership question and never an allowance one.

// shareCookieFor mints the access cookie a recipient holds after following their mailed link, so
// a test request can arrive as that recipient without going through the mail.
func shareCookieFor(t *testing.T, resourceType int, resourceId string, recipientId int) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	shareaccess.WriteCookie(w, httptest.NewRequest("GET", "/", nil), resourceType, resourceId, recipientId)
	cookies := w.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	return cookies[0]
}

// shareWithTwoRecipients stores a file limited to three downloads, shared with two people who get
// three each, and returns their recipient ids.
func shareWithTwoRecipients(t *testing.T, fileId, spentEmail, waitingEmail string) (int, int) {
	t.Helper()
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "per-recipient-metadata.txt",
		Size:               "42 B",
		SizeBytes:          42,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ContentType:        "text/plain",
		DownloadsRemaining: 3,
		UnlimitedTime:      true,
		UserId:             999,
	})
	spent := database.SaveShareRecipient(models.ShareRecipient{Email: spentEmail, CreatedAt: time.Now().Unix()})
	waiting := database.SaveShareRecipient(models.ShareRecipient{Email: waitingEmail, CreatedAt: time.Now().Unix()})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{spent, waiting}, 999, 3)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(spent)
		database.DeleteShareRecipient(waiting)
		database.DeleteMetaData(fileId)
	})
	return spent, waiting
}

// metadataFor calls /pubapi/file as the holder of one access cookie.
func metadataFor(t *testing.T, fileId string, cookie *http.Cookie) (int, map[string]interface{}) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/pubapi/file?id="+fileId, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	pubApiFileMetadata(w, r)
	var body map[string]interface{}
	test.IsNil(t, json.NewDecoder(w.Body).Decode(&body))
	return w.Code, body
}

func TestPublicApiFileMetadataRefusesExhaustedRecipient(t *testing.T) {
	fileId := helper.GenerateRandomString(16)
	spent, waiting := shareWithTwoRecipients(t, fileId,
		"metadata-spent@example.com", "metadata-waiting@example.com")

	spentCookie := shareCookieFor(t, models.ShareResourceFile, fileId, spent)
	waitingCookie := shareCookieFor(t, models.ShareResourceFile, fileId, waiting)

	// Both are entitled to the record to begin with.
	code, body := metadataFor(t, fileId, spentCookie)
	test.IsEqualInt(t, code, http.StatusOK)
	test.IsEqualString(t, body["name"].(string), "per-recipient-metadata.txt")

	// The first recipient takes all three of the downloads the owner set. Leeway 0, so each
	// window closes at once and the third leaves them finished rather than mid-transfer.
	for round := 0; round < 3; round++ {
		granted, _ := database.AcquireShareGrantDownload(models.ShareResourceFile, fileId,
			spent, time.Now().Unix(), 0)
		test.IsEqualBool(t, granted, true)
	}

	// The answer they get now is the one an invented id gets - not "forbidden", which would
	// confirm the id names a real file.
	code, body = metadataFor(t, fileId, spentCookie)
	test.IsEqualInt(t, code, http.StatusNotFound)
	test.IsEqualString(t, body["error"].(string), "not found")

	unknownCode, unknownBody := metadataFor(t, helper.GenerateRandomString(16), nil)
	test.IsEqualInt(t, unknownCode, http.StatusNotFound)
	test.IsEqual(t, body, unknownBody)

	// The second recipient is untouched: their own budget is intact, so they still hold the file.
	code, body = metadataFor(t, fileId, waitingCookie)
	test.IsEqualInt(t, code, http.StatusOK)
	test.IsEqual(t, body["isAuthorised"], true)
	test.IsEqualString(t, body["name"].(string), "per-recipient-metadata.txt")
}

// TestPublicApiFileMetadataRateLimitsExhaustedRecipient proves the refusal goes through
// respondPubApiNotFound rather than writing its own 404. Skipping the limiter would make a
// real-but-finished id answer faster than an invented one, which tells a prober which ids are
// real - the same timing oracle TestPublicApiFileMetadataRateLimitsUnauthorisedIdentityRecipient
// closed for a non-recipient, and it must not be reopened by a new refusal path.
//
// Rate limiting is switched on only for the duration of this test, against an IP no other test
// drives through this handler, so as not to disturb - or be disturbed by - shared limiter state.
func TestPublicApiFileMetadataRateLimitsExhaustedRecipient(t *testing.T) {
	ratelimiter.SetUnitTestMode(false)
	t.Cleanup(func() { ratelimiter.SetUnitTestMode(true) })

	fileId := helper.GenerateRandomString(16)
	spent, _ := shareWithTwoRecipients(t, fileId,
		"metadata-timing-spent@example.com", "metadata-timing-waiting@example.com")
	cookie := shareCookieFor(t, models.ShareResourceFile, fileId, spent)

	for round := 0; round < 3; round++ {
		granted, _ := database.AcquireShareGrantDownload(models.ShareResourceFile, fileId,
			spent, time.Now().Unix(), 0)
		test.IsEqualBool(t, granted, true)
	}

	const ip = "203.0.113.202:54321"
	call := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/pubapi/file?id="+fileId, nil)
		r.AddCookie(cookie)
		r.RemoteAddr = ip
		pubApiFileMetadata(w, r)
		return w.Code
	}

	// WaitOnFailedId's burst of 10 lets the first ten calls through without blocking.
	for i := 0; i < 10; i++ {
		test.IsEqualInt(t, call(), http.StatusNotFound)
	}

	start := time.Now()
	test.IsEqualInt(t, call(), http.StatusNotFound)
	elapsed := time.Since(start)
	if elapsed < 700*time.Millisecond {
		t.Fatalf("call past the burst returned in %v; expected WaitOnFailedId to have throttled it to ~1s, meaning the rate limiter was never consulted", elapsed)
	}
}

// TestSingleFileLastRecipientDenialAttributesRecipient covers the other end of a share's life.
// Once the last recipient has spent their last download the file itself is over, so the next
// request is refused at the door by storage.GetFile rather than at the per-recipient allowance
// check - and that final entry in the share's audit trail must still name who was asking, or the
// one denial that closes a share would be the one with nobody's name on it.
func TestSingleFileLastRecipientDenialAttributesRecipient(t *testing.T) {
	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "last_recipient.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ContentType:        "text/plain",
		DownloadsRemaining: 1,
		UnlimitedTime:      true,
		UserId:             999,
	})
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "last-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 1)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	granted, _ := database.AcquireShareGrantDownload(models.ShareResourceFile, fileId,
		recipientId, time.Now().Unix(), 0)
	test.IsEqualBool(t, granted, true)

	cookie := shareCookieFor(t, models.ShareResourceFile, fileId, recipientId)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/downloadFile?id="+fileId, nil)
	r.AddCookie(cookie)
	serveFile(fileId, true, w, r)

	entry := lastDownloadEntry(t, fileId, logging.OutcomeDenied)
	test.IsEqualBool(t, entry.Actor.Anonymous, false)
	test.IsEqualInt(t, entry.Actor.RecipientId, recipientId)
	test.IsEqualString(t, entry.Actor.RecipientEmail, "last-recipient@example.com")
	test.IsEqualString(t, entry.Error, "unknown, expired, or invalid file id")
}
