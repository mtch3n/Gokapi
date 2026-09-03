//go:build !integration && test

package filebundle

import (
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
)

// This file tests what a deleted folder leaves behind. Deleting one disposes of its members, whose
// rows survive for the metadata retention period so their owner still sees what was deleted - and
// the folder has to outlive those rows, or they name a bundle that no longer exists and the file
// list has nothing left to group them under. Every test below drives storage.CleanUp itself rather
// than waiting on the background sweep Delete starts, because the point being tested is the state
// the sweep settles on, not how quickly it gets there.

func TestMain(m *testing.M) {
	testconfiguration.Create(true)
	configuration.Load()
	configuration.ConnectDatabase()
	var testserver *httptest.Server
	if testconfiguration.UseMockS3Server() {
		testserver = testconfiguration.StartS3TestServer()
	}
	exitVal := m.Run()
	testconfiguration.Delete()
	if testserver != nil {
		testserver.Close()
	}
	os.Exit(exitVal)
}

// setRetention overrides GOKAPI_METADATA_RETENTION for the calling test, restoring this package's
// test default (retention disabled, see testconfiguration.SetDirEnv) once it finishes. Safe against
// the other tests here, none of which run under t.Parallel(): a non-parallel test always runs to
// completion, restore included, before the next one starts.
func setRetention(t *testing.T, value string) {
	t.Helper()
	os.Setenv("GOKAPI_METADATA_RETENTION", value)
	t.Cleanup(func() { os.Setenv("GOKAPI_METADATA_RETENTION", "0") })
}

// saveMember adds a member file to a bundle, with a content blob really on disk so that disposing
// of it takes the same path a real member would, and returns its id.
func saveMember(t *testing.T, bundleId string) string {
	t.Helper()
	sha1 := "folderdeletetest_" + helper.GenerateRandomString(16)
	err := os.WriteFile(configuration.Get().DataDir+"/"+sha1, []byte("member content"), 0600)
	test.IsNil(t, err)
	id := "folderdeletemember_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               id + ".txt",
		SHA1:               sha1,
		Size:               "14 B",
		SizeBytes:          14,
		UserId:             999,
		BundleId:           bundleId,
		UnlimitedTime:      true,
		UnlimitedDownloads: true,
	})
	return id
}

// TestDeleteKeepsFolderWhileItsDeletedFilesRemain is the behaviour the whole path exists for: with
// a retention window set, the member keeps its row, still names its folder, and the folder is still
// there for it to be grouped under.
func TestDeleteKeepsFolderWhileItsDeletedFilesRemain(t *testing.T) {
	setRetention(t, "1h")
	bundle := Create("delete-keeps-folder", 999)
	memberId := saveMember(t, bundle.Id)
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundle.Id})
	})

	Delete(bundle)
	storage.CleanUp(false)

	member, ok := database.GetMetaDataById(memberId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, member.IsDisposed(), true)
	test.IsEqualInt(t, member.DisposalReason, models.DisposalReasonDeleted)
	test.IsEqualString(t, member.BundleId, bundle.Id)

	stored, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, stored.Id, bundle.Id)
	test.IsEqualBool(t, stored.DeletedAt != 0, true)
}

// TestDeleteCollectsFolderOnceItsDeletedFilesArePurged is the end of that window. The folder goes
// with the last member row, in the same sweep that purges it - not while those rows are still
// listed, and not a day later because the folder happened to be young when it was deleted.
func TestDeleteCollectsFolderOnceItsDeletedFilesArePurged(t *testing.T) {
	setRetention(t, "1h")
	bundle := Create("delete-collects-folder", 999)
	memberId := saveMember(t, bundle.Id)
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundle.Id})
	})

	Delete(bundle)
	storage.CleanUp(false)

	_, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, true)

	// Move the member's disposal two hours into the past, so the one-hour window set above has
	// elapsed for it.
	member, ok := database.GetMetaDataById(memberId)
	test.IsEqualBool(t, ok, true)
	member.DisposedAt = time.Now().Add(-2 * time.Hour).Unix()
	database.SaveMetaData(member)

	storage.CleanUp(false)

	_, ok = database.GetMetaDataById(memberId)
	test.IsEqualBool(t, ok, false)
	_, ok = database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, false)
}

// TestDeleteWithRetentionDisabledLeavesNoFolderBehind covers the other end of the setting. With no
// retention there is no history to keep, so the member row goes in the very sweep that disposes of
// it, and the folder must go in that same sweep rather than lingering with nothing under it.
func TestDeleteWithRetentionDisabledLeavesNoFolderBehind(t *testing.T) {
	setRetention(t, "0")
	bundle := Create("delete-retention-disabled", 999)
	memberId := saveMember(t, bundle.Id)
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundle.Id})
	})

	Delete(bundle)
	storage.CleanUp(false)

	_, ok := database.GetMetaDataById(memberId)
	test.IsEqualBool(t, ok, false)
	_, ok = database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, false)
}

// TestDeleteEmptyFolderDoesNotHoldItForTheGracePeriod is the case a deletion mark is needed for. An
// empty folder has no member row to be kept alive by, which is indistinguishable from a folder
// whose first upload is still in flight - and models.FileBundleGracePeriod would hold that one for
// a day. A folder its owner deleted can gain no members, so it goes at once, whatever the retention
// setting says about files.
func TestDeleteEmptyFolderDoesNotHoldItForTheGracePeriod(t *testing.T) {
	setRetention(t, "24h")
	bundle := Create("delete-empty-folder", 999)
	t.Cleanup(func() { database.DeleteFileBundle(models.FileBundle{Id: bundle.Id}) })

	Delete(bundle)
	storage.CleanUp(false)

	_, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, false)
}

// TestDeleteStripsCredentialsFromTheRetainedFolder holds the retained folder row to the same rule
// storage.disposeFile holds a retained file record to: a record kept as history carries no
// credential material. The row now outlives the deletion, so the folder's own password, its stored
// share key and the login tokens issued against it must not outlive it with it.
func TestDeleteStripsCredentialsFromTheRetainedFolder(t *testing.T) {
	setRetention(t, "1h")
	bundle := Create("delete-strips-credentials", 999)
	bundle.PasswordHash = "somehash"
	bundle.EncryptedSharePassword = []byte("encrypted-share-password")
	database.SaveFileBundle(bundle)
	memberId := saveMember(t, bundle.Id)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "folder-delete-" + bundle.Id + "@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceBundle, bundle.Id, []int{recipientId}, 999, 0)
	tokenHash := "folder-delete-token-" + bundle.Id
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    tokenHash,
		RecipientId:  recipientId,
		ResourceType: models.ShareResourceBundle,
		ResourceId:   bundle.Id,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteShareGrants(models.ShareResourceBundle, bundle.Id)
		database.DeleteShareRecipient(recipientId)
		database.DeleteFileBundle(models.FileBundle{Id: bundle.Id})
	})

	Delete(bundle)
	storage.CleanUp(false)

	stored, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, stored.PasswordHash, "")
	test.IsEqualInt(t, len(stored.EncryptedSharePassword), 0)

	token, ok := database.GetShareLoginToken(tokenHash)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, token.IsRevoked, true)

	// The grant itself is history, the same as a disposed file's, and stays until the row it
	// belongs to is finally collected.
	test.IsEqualInt(t, len(database.GetShareGrants(models.ShareResourceBundle, bundle.Id)), 1)
}
