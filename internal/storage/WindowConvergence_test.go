//go:build !integration && test

package storage

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

// This file tests the download window: access to a resource ends at whichever comes first, its
// expiry or the close of the window that its first pickup opened. It covers the two halves that
// make that one rule instead of four - the leeway is a value LeewayFor decides once, and a
// folder member's axes are the folder's, resolved once by downloadAccessOf - and the disposal
// behaviour that follows from both.
//
// Named to sort after FileServing_test.go, for the same reason MetadataRetention_test.go is: the
// tests here run CleanUp over the whole database, which disposes of the shared fixtures that
// file's tests still expect to find, and Go runs a package's tests in source file order.

// setDownloadLeeway overrides GOKAPI_DOWNLOAD_SESSION_LEEWAY and GOKAPI_DOWNLOAD_SESSION_SIGN_KEY
// for the calling test, restoring this package's test defaults once it finishes.
// configuration.Load re-parses the environment, which is what DownloadLeeway and
// DownloadSessionSignKey read. Safe against the other tests in this package for the same reason
// MetadataRetention_test.go's setRetention is: none of them run under t.Parallel().
func setDownloadLeeway(t *testing.T, value string) {
	t.Helper()
	os.Setenv("GOKAPI_DOWNLOAD_SESSION_LEEWAY", value)
	os.Setenv("GOKAPI_DOWNLOAD_SESSION_SIGN_KEY", "test_key_that_is_at_least_32_characters_long__")
	configuration.Load()
	t.Cleanup(func() {
		os.Setenv("GOKAPI_DOWNLOAD_SESSION_LEEWAY", "0")
		os.Unsetenv("GOKAPI_DOWNLOAD_SESSION_SIGN_KEY")
		configuration.Load()
	})
}

// abortingResponseWriter stands in for a recipient whose connection drops part way through a
// transfer: it accepts the headers and the first byte, then fails every further write, which is
// what http.ServeContent sees when a client hangs up.
type abortingResponseWriter struct {
	header  http.Header
	written int
}

func (w *abortingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *abortingResponseWriter) Write(content []byte) (int, error) {
	if w.written > 0 {
		return 0, errors.New("connection reset by peer")
	}
	w.written = 1
	return 1, nil
}

func (w *abortingResponseWriter) WriteHeader(int) {}

// TestServeFileRefusesATokenlessRetryInsideTheWindow pins the rule that replaced the free ride.
//
// The window used to make a spent file serve anyone who asked, for nothing, until it closed: this
// test asserted exactly that, and it was the end-to-end statement of the defect - a file limited
// to one download served twice, with the counter moving once. A window is a timestamp on the
// file's row, so "inside the window" identified nobody, and the recipient the leeway was meant to
// protect was indistinguishable from anyone else holding the link.
//
// This test asserts the current behaviour: a caller arriving with nothing to prove they opened
// the window gets nothing, even while the window is still open. The session token scheme binds
// window access to a specific recipient id, so the window remains protected.
func TestServeFileRefusesATokenlessRetryInsideTheWindow(t *testing.T) {
	setDownloadLeeway(t, "1h")
	sha1 := writeBlob(t, "the whole body, delivered on the retry")
	id := "windowretry_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "windowretry.txt",
		SHA1:               sha1,
		ContentType:        "text/plain",
		Size:               "38 B",
		SizeBytes:          38,
		DownloadsRemaining: 1,
		UnlimitedTime:      true,
	})

	file, ok := GetFile(id)
	test.IsEqualBool(t, ok, true)
	aborted := &abortingResponseWriter{}
	test.IsEqualBool(t, ServeFile(file, aborted, httptest.NewRequest("GET", "/"+id, nil), true, true, false, true), true)

	spent, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, spent.DownloadsRemaining, 0)
	test.IsEqualBool(t, spent.WindowOpenedAt > 0, true)

	// The window is open, so the row is not yet disposed and the file is still on disk - but a
	// second caller presenting no token is refused, and spends nothing trying.
	w := httptest.NewRecorder()
	test.IsEqualBool(t, ServeFile(spent, w, httptest.NewRequest("GET", "/"+id, nil), true, true, false, true), false)

	after, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, after.DownloadsRemaining, 0)
	test.IsEqualInt(t, after.DownloadCount, 1)
}

// TestServeFileRefusedOnceWindowClosed is the other half: once the window has closed, the spent
// allowance is final again.
func TestServeFileRefusedOnceWindowClosed(t *testing.T) {
	setDownloadLeeway(t, "1h")
	sha1 := writeBlob(t, "closed")
	id := "windowclosed_" + helper.GenerateRandomString(8)
	file := models.File{
		Id:                 id,
		Name:               "windowclosed.txt",
		SHA1:               sha1,
		ContentType:        "text/plain",
		Size:               "6 B",
		SizeBytes:          6,
		DownloadsRemaining: 0,
		UnlimitedTime:      true,
		WindowOpenedAt:     time.Now().Add(-2 * time.Hour).Unix(),
	}
	database.SaveMetaData(file)

	w := httptest.NewRecorder()
	test.IsEqualBool(t, ServeFile(file, w, httptest.NewRequest("GET", "/"+id, nil), true, true, false, true), false)
	test.IsEqualInt(t, w.Body.Len(), 0)
}

// TestSecretIsNotReReadableInsideAnyWindow proves LeewayFor's one exception: the leeway rescues a
// broken transfer, and a secret is one short response with nothing to resume, so it gets none -
// however long the configured window is for everything else.
func TestSecretIsNotReReadableInsideAnyWindow(t *testing.T) {
	setDownloadLeeway(t, "24h")
	sha1 := writeBlob(t, "hunter2")
	id := "secret_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "secret.txt",
		SHA1:               sha1,
		ContentType:        "application/x-exchangepoint-secret",
		Size:               "7 B",
		SizeBytes:          7,
		DownloadsRemaining: 1,
		UnlimitedTime:      true,
	})

	file, ok := GetFile(id)
	test.IsEqualBool(t, ok, true)
	w := httptest.NewRecorder()
	test.IsEqualBool(t, ServeFile(file, w, httptest.NewRequest("GET", "/"+id, nil), true, true, false, true), true)
	content, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	test.IsEqualString(t, string(content), "hunter2")

	// Read once, gone at once - the reveal is final, unlike an ordinary file's transfer.
	_, ok = GetFile(id)
	test.IsEqualBool(t, ok, false)
	revealed, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, IsExpiredFile(revealed, time.Now().Unix()), true)
}

// TestStatusAndExpiryFollowTheWindow covers the owner's view: a one-pickup file with its window
// still open is refused by the serving predicate (IsExpiredFile, via IsSpent - R1: the ordinary
// link is dead for everyone the moment the allowance is spent, window or not) while the owner's
// OWN view of it (File.Status, still IsExhausted-based - the IsSpent branch is a separate, later
// commit) reports it active until the window actually closes. The two deliberately disagree while
// the window is open: one says "nothing to hand a plain request", the other says "not disposed
// of yet, and the owner can still raise the limit" - see the leeway-session-token plan §4/§5.
func TestStatusAndExpiryFollowTheWindow(t *testing.T) {
	setDownloadLeeway(t, "1h")
	id := "windowstatus_" + helper.GenerateRandomString(8)
	file := models.File{
		Id:                 id,
		Name:               "windowstatus.txt",
		SHA1:               writeBlob(t, "status"),
		DownloadsRemaining: 0,
		UnlimitedTime:      true,
		WindowOpenedAt:     time.Now().Unix(),
	}
	database.SaveMetaData(file)

	timeNow := time.Now().Unix()
	test.IsEqualBool(t, IsExpiredFile(file, timeNow), true)
	test.IsEqualString(t, file.Status(DownloadAccessOf(file), timeNow), models.StatusActive)

	file.WindowOpenedAt = time.Now().Add(-2 * time.Hour).Unix()
	database.SaveMetaData(file)
	test.IsEqualBool(t, IsExpiredFile(file, timeNow), true)
	test.IsEqualString(t, file.Status(DownloadAccessOf(file), timeNow), models.StatusDownloaded)
}

// TestCleanUpRespectsTheWindow proves disposal waits for the window to close, so a retry always
// still has content to fetch.
func TestCleanUpRespectsTheWindow(t *testing.T) {
	setDownloadLeeway(t, "1h")
	setRetention(t, "24h")
	sha1 := writeBlob(t, "cleanupwindow")
	id := "windowcleanup_" + helper.GenerateRandomString(8)
	file := models.File{
		Id:                 id,
		Name:               "windowcleanup.txt",
		SHA1:               sha1,
		DownloadsRemaining: 0,
		UnlimitedTime:      true,
		WindowOpenedAt:     time.Now().Unix(),
	}
	database.SaveMetaData(file)

	CleanUp(false)
	stored, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), false)
	test.FileExists(t, configuration.Get().DataDir+"/"+sha1)

	file.WindowOpenedAt = time.Now().Add(-2 * time.Hour).Unix()
	database.SaveMetaData(file)
	CleanUp(false)
	stored, ok = database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonDownloaded)
}

// saveBundleWithMembers stores a folder and count members of it, each with an allowance and an
// expiry of its own that the folder is supposed to override entirely, and returns the member ids.
func saveBundleWithMembers(t *testing.T, bundle models.FileBundle, count int) []string {
	t.Helper()
	database.SaveFileBundle(bundle)
	t.Cleanup(func() { database.DeleteFileBundle(bundle) })
	ids := make([]string, 0, count)
	for i := 0; i < count; i++ {
		id := "bundlemember_" + helper.GenerateRandomString(8)
		database.SaveMetaData(models.File{
			Id:                 id,
			Name:               "member.txt",
			SHA1:               writeBlob(t, "member"),
			DownloadsRemaining: 5,
			ExpireAt:           time.Now().Add(365 * 24 * time.Hour).Unix(),
			BundleId:           bundle.Id,
		})
		ids = append(ids, id)
	}
	return ids
}

// TestCleanUpDisposesEveryMemberWhenFolderIsExhausted is the folder half of the one rule: one
// visit spends the folder's allowance, whichever member it touched, so when that allowance runs
// out every member goes at once. Before this, access converged on the folder but disposal did
// not, and an exhausted folder kept its members' content on disk indefinitely.
func TestCleanUpDisposesEveryMemberWhenFolderIsExhausted(t *testing.T) {
	setRetention(t, "24h")
	bundle := models.FileBundle{
		Id:                 "exhaustedbundle_" + helper.GenerateRandomString(8),
		Name:               "exhausted",
		CreationDate:       time.Now().Unix(),
		DownloadsRemaining: 1,
		ExpireAt:           time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	ids := saveBundleWithMembers(t, bundle, 3)

	test.IsEqualBool(t, database.AcquireBundleDownload(bundle.Id, time.Now().Unix()), true)

	CleanUp(false)

	for _, id := range ids {
		stored, ok := database.GetMetaDataById(id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualBool(t, stored.IsDisposed(), true)
		test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonDownloaded)
	}
	// The folder row itself survives its members' disposal, so the owner keeps seeing the folder
	// with its deleted children for the retention period.
	_, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, true)
}

// TestCleanUpDisposesEveryMemberWhenFolderExpires is the same convergence on the expiry axis: a
// member's own ExpireAt is inert, so an expired folder takes members with a far-future one.
func TestCleanUpDisposesEveryMemberWhenFolderExpires(t *testing.T) {
	setRetention(t, "24h")
	bundle := models.FileBundle{
		Id:                 "expiredbundle_" + helper.GenerateRandomString(8),
		Name:               "expired",
		CreationDate:       time.Now().Unix(),
		DownloadsRemaining: 5,
		ExpireAt:           time.Now().Add(-time.Hour).Unix(),
	}
	ids := saveBundleWithMembers(t, bundle, 2)

	CleanUp(false)

	for _, id := range ids {
		stored, ok := database.GetMetaDataById(id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualBool(t, stored.IsDisposed(), true)
		test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonExpired)
	}
}

// TestCleanUpKeepsMemberWithStaleOwnCounter is the mirror image, and the second live failure the
// folder-unit change left behind: a member whose own counter reached zero long ago must not be
// disposed of while its folder still has allowance, or the folder silently loses a file its
// owner never spent.
func TestCleanUpKeepsMemberWithStaleOwnCounter(t *testing.T) {
	setRetention(t, "24h")
	bundle := models.FileBundle{
		Id:                 "livebundle_" + helper.GenerateRandomString(8),
		Name:               "live",
		CreationDate:       time.Now().Unix(),
		DownloadsRemaining: 5,
		ExpireAt:           time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	database.SaveFileBundle(bundle)
	t.Cleanup(func() { database.DeleteFileBundle(bundle) })

	sha1 := writeBlob(t, "stale")
	id := "stalemember_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "stale.txt",
		SHA1:               sha1,
		DownloadsRemaining: 0,
		ExpireAt:           time.Now().Add(-time.Hour).Unix(),
		BundleId:           bundle.Id,
	})

	CleanUp(false)

	stored, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), false)
	test.FileExists(t, configuration.Get().DataDir+"/"+sha1)
	// And the member is still servable, which is what makes extending a folder's expiry past its
	// members' own actually take effect rather than being undone by the next sweep.
	_, ok = GetFile(id)
	test.IsEqualBool(t, ok, true)
}

// TestCleanUpUnbundledFileIsUnchanged is the regression guard for everything that is not in a
// folder: with no folder to defer to and no leeway configured, disposal is exactly what it was.
func TestCleanUpUnbundledFileIsUnchanged(t *testing.T) {
	setRetention(t, "24h")
	sha1 := writeBlob(t, "unbundled")
	id := "unbundled_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "unbundled.txt",
		SHA1:               sha1,
		DownloadsRemaining: 0,
		UnlimitedTime:      true,
	})

	CleanUp(false)

	stored, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonDownloaded)
	test.FileDoesNotExist(t, configuration.Get().DataDir+"/"+sha1)
}
