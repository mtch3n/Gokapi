//go:build !integration && test

package webserver

import (
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

// TestMemberOfAMissingFolderIsNotRedirected is the regression test for live files whose folder no
// longer exists. A folder deleted by an older build left its members' rows behind still naming it;
// nothing enforces that reference, so the member link redirected to a folder endpoint that then
// answered not-found, and the file became undownloadable while still being listed as active.
// Production had ten such files.
//
// All three member links resolve the folder through governingFolderOf, so this covers the
// download, the public metadata and the password submit together.
func TestMemberOfAMissingFolderIsNotRedirected(t *testing.T) {
	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "orphan.txt",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		Size:               "3 B",
		SizeBytes:          3,
		UserId:             999,
		BundleId:           "a-folder-that-does-not-exist",
		ExpireAt:           time.Now().Add(72 * time.Hour).Unix(),
		DownloadsRemaining: 1,
	})
	t.Cleanup(func() { database.DeleteMetaData(fileId) })

	// Sanity: the fixture really is a live member by the test the redirect used to rely on, so
	// this proves the missing FOLDER is what stops the redirect, not the file being ineligible.
	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsBundleMember(stored.BundleId), true)

	_, redirected := governingFolderOf(fileId)
	test.IsEqualBool(t, redirected, false)

	// A member whose folder DOES exist is still redirected, so the fix did not simply switch the
	// folder behaviour off.
	bundleId := helper.GenerateRandomString(12)
	database.SaveFileBundle(models.FileBundle{
		Id: bundleId, Name: "real folder", UserId: 999,
		CreationDate: time.Now().Unix(), UnlimitedTime: true, UnlimitedDownloads: true,
	})
	memberId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id: memberId, Name: "member.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		Size: "3 B", SizeBytes: 3, UserId: 999, BundleId: bundleId,
		ExpireAt: time.Now().Add(72 * time.Hour).Unix(), DownloadsRemaining: 1,
	})
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundleId})
	})

	resolved, redirected := governingFolderOf(memberId)
	test.IsEqualBool(t, redirected, true)
	test.IsEqualString(t, resolved, bundleId)
}
