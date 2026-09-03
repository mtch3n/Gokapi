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

// setShareLeeway overrides GOKAPI_DOWNLOAD_LEEWAY for the calling test, restoring this package's
// default of 0 once it finishes. configuration.GetEnvironment hands back a cached value, so
// configuration.Load has to re-parse before storage.DownloadLeeway sees the override. Safe here
// for the same reason storage's own setDownloadLeeway is: nothing in this package runs under
// t.Parallel.
func setShareLeeway(t *testing.T, value string) {
	t.Helper()
	os.Setenv("GOKAPI_DOWNLOAD_LEEWAY", value)
	configuration.Load()
	t.Cleanup(func() {
		os.Setenv("GOKAPI_DOWNLOAD_LEEWAY", "0")
		configuration.Load()
	})
}

// TestResolveShareResourceRefusesSpentFile covers a file whose download allowance is spent but
// whose window is still open. shareaccess.resolveDownloadsAllowed inherits the resource's own
// remaining downloads for every caller that names no number - which is every caller today - and a
// stored allowance of zero means unlimited, so sharing such a file used to hand each recipient an
// unlimited budget: the exact opposite of the limit its owner set.
//
// The leeway override is what makes this test mean anything rather than merely pass. At the
// package default of 0 the file would already be exhausted, storage.GetFile would refuse it, and
// resolveShareResource would never reach the allowance guard at all - so the GetFile assertion
// below is the precondition, not decoration: it proves the refusal is the guard's doing and not
// the liveness check's.
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

	stored, ok := storage.GetFile(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 0)

	w := httptest.NewRecorder()
	_, resolvedOk := resolveShareResource(w, models.ShareResourceFile, fileId, owner)
	test.IsEqualBool(t, resolvedOk, false)
	test.IsEqualInt(t, w.Code, http.StatusBadRequest)
}

// TestResolveShareResourceRefusesSpentFolder is the same defect on the folder path, which reaches
// it through a different gate: the folder is admitted by bundleHasOnlyLiveMembers rather than by
// storage.GetFile, and resolveDownloadsAllowed then inherits the FOLDER's remaining downloads.
// A member resolves its access from its folder, so an open folder window keeps every member live
// and the liveness gate passes while the allowance is spent.
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

	test.IsEqualBool(t, bundleHasOnlyLiveMembers(bundle.Id), true)

	w := httptest.NewRecorder()
	_, resolvedOk := resolveShareResource(w, models.ShareResourceBundle, bundle.Id, owner)
	test.IsEqualBool(t, resolvedOk, false)
	test.IsEqualInt(t, w.Code, http.StatusBadRequest)
}
