package webserver

import (
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
)

// TestDeletedFolderOutlivesItsDeletedMembers is the regression test for a folder vanishing out
// from under the files it contained. Deleting a folder disposes of its members, whose ROWS
// survive for the metadata retention period so the owner still sees them badged as deleted -
// but the bundle row was removed immediately, so those rows pointed at a bundle that no longer
// existed and the file list rendered them flat with no folder to group them under.
func TestDeletedFolderOutlivesItsDeletedMembers(t *testing.T) {
	bundle := filebundle.Create("folder-delete-retention", 999)
	memberId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 memberId,
		Name:               "kept.txt",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		Size:               "3 B",
		SizeBytes:          3,
		UserId:             999,
		BundleId:           bundle.Id,
		ExpireAt:           time.Now().Add(72 * time.Hour).Unix(),
		DownloadsRemaining: 1,
	})
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundle.Id})
	})

	filebundle.Delete(bundle)

	// The member's row is kept, as it is for any deleted file.
	member, ok := database.GetMetaDataById(memberId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, member.BundleId, bundle.Id)

	// And the folder it names is still there for it to be grouped under.
	stored, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, stored.Id, bundle.Id)
}

// TestDeletedEmptyFolderIsRemovedAtOnce guards the other half: a folder with no member rows to
// outlive has nothing to keep it, and must not linger waiting for the cleanup sweep.
func TestDeletedEmptyFolderIsRemovedAtOnce(t *testing.T) {
	bundle := filebundle.Create("folder-delete-empty", 999)

	filebundle.Delete(bundle)

	_, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, false)
}
