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

// setDownloadLeeway overrides GOKAPI_DOWNLOAD_LEEWAY for the calling test, restoring this
// package's test default of 0 once it finishes. configuration.Load re-parses the environment,
// which is what DownloadLeeway reads. Safe against the other tests in this package for the same
// reason MetadataRetention_test.go's setRetention is: none of them run under t.Parallel().
func setDownloadLeeway(t *testing.T, value string) {
	t.Helper()
	os.Setenv("GOKAPI_DOWNLOAD_LEEWAY", value)
	configuration.Load()
	t.Cleanup(func() {
		os.Setenv("GOKAPI_DOWNLOAD_LEEWAY", "0")
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

// TestServeFileRetriesAbortedTransferInsideWindow is the regression test for the failure the
// window exists to remove: a one-pickup file whose first transfer breaks part way through used
// to leave the recipient with nothing, the allowance spent and the file due for deletion.
func TestServeFileRetriesAbortedTransferInsideWindow(t *testing.T) {
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

	// The file is still reachable, because its window is open, and the retry costs nothing.
	retry, ok := GetFile(id)
	test.IsEqualBool(t, ok, true)
	w := httptest.NewRecorder()
	test.IsEqualBool(t, ServeFile(retry, w, httptest.NewRequest("GET", "/"+id, nil), true, true, false, true), true)
	content, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	test.IsEqualString(t, string(content), "the whole body, delivered on the retry")

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

// TestStatusAndExpiryFollowTheWindow covers the owner's view: a one-pickup file reports active
// with nothing remaining while its window is open, and downloaded once it closes.
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
	test.IsEqualBool(t, IsExpiredFile(file, timeNow), false)
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

	granted, opened := database.AcquireBundleDownload(bundle.Id, time.Now().Unix(), 0)
	test.IsEqualBool(t, granted, true)
	test.IsEqualBool(t, opened, true)

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

// --- The owner's limit bounds a recipient's grant ---
//
// A share is one of the paths the one rule has to cover, and it was the one door where the
// owner's own limit did not apply at all: the share dialog sends 0 for "unlimited" unless the
// owner types a number, and that 0 used to mean "no limit" outright, so a file the owner limited
// to a single download handed its recipient an unlimited budget. The owner may narrow what they
// allowed; they may not be made to widen it.

// saveGrantedFile stores a file with the given allowance, shares it with one recipient at the
// given granted allowance, and returns the resolved grant.
func saveGrantedFile(t *testing.T, allowedDownloads int, unlimited bool, granted int) models.ShareGrant {
	t.Helper()
	id := "granted_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "granted.txt",
		SHA1:               writeBlob(t, "granted"),
		DownloadsRemaining: allowedDownloads,
		UnlimitedDownloads: unlimited,
		UnlimitedTime:      true,
	})
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "recipient_" + helper.GenerateRandomString(8) + "@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, id, []int{recipientId}, 1, granted)
	grants := database.GetShareGrants(models.ShareResourceFile, id)
	test.IsEqualInt(t, len(grants), 1)
	return grants[0]
}

// TestGrantAllowanceUnlimitedGrantResolvesToTheOwnersLimit is the case Ming reported: a file
// limited to one download, shared with someone, showing "Unlimited" as their budget.
func TestGrantAllowanceUnlimitedGrantResolvesToTheOwnersLimit(t *testing.T) {
	grant := saveGrantedFile(t, 1, false, 0)
	test.IsEqualInt(t, GrantAllowanceOf(grant), 1)
}

// TestGrantAllowanceOwnerMayNarrow: a grant below the owner's limit is the owner's own decision
// and stands.
func TestGrantAllowanceOwnerMayNarrow(t *testing.T) {
	grant := saveGrantedFile(t, 5, false, 2)
	test.IsEqualInt(t, GrantAllowanceOf(grant), 2)
}

// TestGrantAllowanceOwnerMayNotWiden: a grant above the owner's limit is capped at it.
func TestGrantAllowanceOwnerMayNotWiden(t *testing.T) {
	grant := saveGrantedFile(t, 2, false, 5)
	test.IsEqualInt(t, GrantAllowanceOf(grant), 2)
}

// TestGrantAllowanceUnlimitedFileStaysUnlimited: there is no limit to inherit, so "no limit of my
// own" really is no limit.
func TestGrantAllowanceUnlimitedFileStaysUnlimited(t *testing.T) {
	grant := saveGrantedFile(t, 0, true, 0)
	test.IsEqualInt(t, GrantAllowanceOf(grant), 0)
}

// TestGrantAllowanceFollowsALaterChangeToTheOwnersLimit pins the snapshot-versus-live decision.
// The allowance is resolved on every read and every download, not written into the grant row when
// it is made, so an owner who lowers a file's limit afterwards - through PUT /api/files/modify or
// PUT /api/folder/modify - lowers what an already-granted recipient may still take. A snapshot
// would have left the recipient holding a budget the owner has since withdrawn.
func TestGrantAllowanceFollowsALaterChangeToTheOwnersLimit(t *testing.T) {
	grant := saveGrantedFile(t, 5, false, 0)
	test.IsEqualInt(t, GrantAllowanceOf(grant), 5)

	file, ok := database.GetMetaDataById(grant.ResourceId)
	test.IsEqualBool(t, ok, true)
	file.DownloadsRemaining = 1
	database.SaveMetaData(file)

	test.IsEqualInt(t, GrantAllowanceOf(grant), 1)
}

// TestGrantAllowanceIsSpentAgainstTheOwnersLimit is the same rule at download time rather than at
// display time. What the recipient has already taken is added back to what the file has left, so
// the budget does not shrink as it is used: a recipient granted the whole of a five-download file
// gets five, and the sixth is refused.
func TestGrantAllowanceIsSpentAgainstTheOwnersLimit(t *testing.T) {
	grant := saveGrantedFile(t, 5, false, 0)
	for i := 0; i < 5; i++ {
		allowed, ok := GrantAllowanceFor(models.ShareResourceFile, grant.ResourceId, grant.RecipientId)
		test.IsEqualBool(t, ok, true)
		granted, _ := database.AcquireShareGrantDownload(models.ShareResourceFile, grant.ResourceId,
			grant.RecipientId, time.Now().Unix(), 0, allowed)
		test.IsEqualBool(t, granted, true)
		// The file's own allowance is spent alongside the grant's, as a real download would.
		file, found := database.GetMetaDataById(grant.ResourceId)
		test.IsEqualBool(t, found, true)
		file.DownloadsRemaining = file.DownloadsRemaining - 1
		database.SaveMetaData(file)
	}

	allowed, ok := GrantAllowanceFor(models.ShareResourceFile, grant.ResourceId, grant.RecipientId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, allowed, 5)
	granted, _ := database.AcquireShareGrantDownload(models.ShareResourceFile, grant.ResourceId,
		grant.RecipientId, time.Now().Unix(), 0, allowed)
	test.IsEqualBool(t, granted, false)
}

// TestGrantAllowanceOnAFolderMemberComesFromTheFolder: a member's own allowance is inert, so the
// folder's is what bounds a grant on it, exactly as it bounds access and disposal.
func TestGrantAllowanceOnAFolderMemberComesFromTheFolder(t *testing.T) {
	bundle := models.FileBundle{
		Id:                 "grantbundle_" + helper.GenerateRandomString(8),
		Name:               "grantbundle",
		CreationDate:       time.Now().Unix(),
		DownloadsRemaining: 2,
		ExpireAt:           time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	database.SaveFileBundle(bundle)
	t.Cleanup(func() { database.DeleteFileBundle(bundle) })

	id := "grantmember_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "member.txt",
		SHA1:               writeBlob(t, "member"),
		DownloadsRemaining: 99,
		ExpireAt:           time.Now().Add(365 * 24 * time.Hour).Unix(),
		BundleId:           bundle.Id,
	})
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "member_" + helper.GenerateRandomString(8) + "@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, id, []int{recipientId}, 1, 0)

	allowed, ok := GrantAllowanceFor(models.ShareResourceFile, id, recipientId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, allowed, 2)
}
