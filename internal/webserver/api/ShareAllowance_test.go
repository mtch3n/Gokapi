package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
)

// setShareLeeway overrides GOKAPI_DOWNLOAD_SESSION_LEEWAY and GOKAPI_DOWNLOAD_SESSION_SIGN_KEY for the
// calling test, restoring this package's defaults once it finishes. configuration.GetEnvironment
// hands back a cached value, so configuration.Load has to re-parse before storage.DownloadLeeway
// sees the override. Safe here for the same reason storage's own setDownloadLeeway is: nothing in
// this package runs under t.Parallel.
func setShareLeeway(t *testing.T, value string) {
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

// TestResolveShareResourceRefusesSpentFile covers a file whose download allowance is spent, with
// its download window still open. Before storage.GetFile enforced R1 (the leeway-session-token
// plan: a spent resource's ordinary link is dead for everyone, in or out of its window), this
// used to reach a separate shareWouldGrantUnlimited guard - moved here because
// shareaccess.resolveDownloadsAllowed inherits the resource's own remaining downloads for every
// caller that names no number, and a stored allowance of zero means unlimited, so sharing a spent
// file used to hand each new recipient an unlimited budget. Now storage.GetFile itself refuses
// the file outright, in or out of its window, so that guard is dead code and was removed with it
// (see bundleHasOnlyLiveMembers's doc comment) - this test now pins the refusal one level up.
func TestResolveShareResourceRefusesSpentFile(t *testing.T) {
	setShareLeeway(t, "1h")
	owner := models.User{
		Id: idAdmin, Name: "TestAdmin", Permissions: models.UserPermissionAll,
		UserLevel: models.UserLevelAdmin, AuthProvider: models.AuthProviderInternal,
	}
	fileId := "shareSpentFile_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id: fileId, Name: "spent.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UserId: owner.Id, UnlimitedTime: true,
		DownloadsRemaining: 0, UnlimitedDownloads: false,
		WindowOpenedAt: time.Now().Unix(),
	})
	t.Cleanup(func() { database.DeleteMetaData(fileId) })

	// The window being open (leeway 1h, WindowOpenedAt just now) is what proves this: a spent
	// file is refused even though its retry window has not closed, not merely because it is
	// altogether exhausted - the harder, R1-specific half of the claim.
	_, ok := storage.GetFile(fileId)
	test.IsEqualBool(t, ok, false)

	w := httptest.NewRecorder()
	_, resolvedOk := resolveShareResource(w, models.ShareResourceFile, fileId, owner)
	test.IsEqualBool(t, resolvedOk, false)
	test.IsEqualInt(t, w.Code, http.StatusNotFound)
}

// TestResolveShareResourceRefusesSpentFolder is the same proof on the folder path, which reaches
// it through a different gate: a member resolves its liveness from its folder (see
// storage.IsExpiredFile), so bundleHasOnlyLiveMembers is what now refuses a folder whose own
// allowance is spent, in or out of its window - the folder's ordinary link is dead for everyone,
// exactly as a file's is, so there is nothing left here for the removed shareWouldGrantUnlimited
// guard to ever have been reached with a spent-but-live folder.
func TestResolveShareResourceRefusesSpentFolder(t *testing.T) {
	setShareLeeway(t, "1h")
	owner := models.User{
		Id: idAdmin, Name: "TestAdmin", Permissions: models.UserPermissionAll,
		UserLevel: models.UserLevelAdmin, AuthProvider: models.AuthProviderInternal,
	}
	bundle := filebundle.Create("TestSpentFolder_"+helper.GenerateRandomString(8), owner.Id)
	bundle.UnlimitedDownloads = false
	bundle.DownloadsRemaining = 0
	bundle.WindowOpenedAt = time.Now().Unix()
	database.SaveFileBundle(bundle)
	memberId := "shareSpentMember_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id: memberId, Name: "member.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UserId: owner.Id, UnlimitedTime: true, BundleId: bundle.Id,
	})
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundle.Id})
	})

	test.IsEqualBool(t, bundleHasOnlyLiveMembers(bundle.Id), false)

	w := httptest.NewRecorder()
	_, resolvedOk := resolveShareResource(w, models.ShareResourceBundle, bundle.Id, owner)
	test.IsEqualBool(t, resolvedOk, false)
	test.IsEqualInt(t, w.Code, http.StatusNotFound)
}
