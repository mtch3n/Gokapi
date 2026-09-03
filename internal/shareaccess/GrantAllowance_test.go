//go:build test

package shareaccess

import (
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

// The owner sets one download limit on the resource and it is each recipient's own budget, so
// that is the number the grant row has to carry. It is resolved when the grant is written rather
// than looked up again at download time, because the grant is the record of what this recipient
// was given and has to say so on its own - the recipient's inbox reads it straight off the row.
//
// The interface deliberately has no control for it and always sends zero, which is why zero has
// to mean "the resource's limit" here and not "unlimited".

// grantedAllowanceOf reads the stored grant back out of the database, so these tests assert on
// the column rather than on whatever GrantAccess happened to return.
func grantedAllowanceOf(t *testing.T, resourceType int, resourceId string) int {
	t.Helper()
	grants := database.GetShareGrants(resourceType, resourceId)
	test.IsEqualInt(t, len(grants), 1)
	return grants[0].DownloadsAllowed
}

func TestGrantAllowanceInheritsTheFilesOwnLimit(t *testing.T) {
	enableMail(t)
	fileId := "allowance-file-limited"
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "limited.pdf",
		DownloadsRemaining: 4,
		ExpireAt:           time.Now().Add(24 * time.Hour).Unix(),
	})
	t.Cleanup(func() { database.DeleteMetaData(fileId) })
	resource := testResource(fileId)

	_, err := GrantAccess(resource, []string{"inherit@example.com"}, testActor(1), 0, "https://x.test/")
	test.IsNil(t, err)

	test.IsEqualInt(t, grantedAllowanceOf(t, models.ShareResourceFile, fileId), 4)
}

func TestGrantAllowanceStaysUnlimitedForAnUnlimitedFile(t *testing.T) {
	enableMail(t)
	fileId := "allowance-file-unlimited"
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "unlimited.pdf",
		DownloadsRemaining: 4,
		UnlimitedDownloads: true,
		ExpireAt:           time.Now().Add(24 * time.Hour).Unix(),
	})
	t.Cleanup(func() { database.DeleteMetaData(fileId) })
	resource := testResource(fileId)

	_, err := GrantAccess(resource, []string{"unlimited@example.com"}, testActor(1), 0, "https://x.test/")
	test.IsNil(t, err)

	// Zero is what models.ShareGrant.DownloadsAllowed uses for unlimited, and an unlimited
	// resource is the one case where a caller asking for zero still gets it.
	test.IsEqualInt(t, grantedAllowanceOf(t, models.ShareResourceFile, fileId), 0)
}

// A caller naming a number of its own is narrowing the share, which is the owner's prerogative,
// so it is honoured over the resource's limit rather than raised to it.
func TestGrantAllowanceHonoursAnExplicitNarrowerNumber(t *testing.T) {
	enableMail(t)
	fileId := "allowance-file-narrowed"
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "narrowed.pdf",
		DownloadsRemaining: 4,
		ExpireAt:           time.Now().Add(24 * time.Hour).Unix(),
	})
	t.Cleanup(func() { database.DeleteMetaData(fileId) })
	resource := testResource(fileId)

	_, err := GrantAccess(resource, []string{"narrowed@example.com"}, testActor(1), 1, "https://x.test/")
	test.IsNil(t, err)

	test.IsEqualInt(t, grantedAllowanceOf(t, models.ShareResourceFile, fileId), 1)
}

// A folder is shared the same way a file is, and its own limit is what its recipients inherit.
func TestGrantAllowanceInheritsTheFoldersOwnLimit(t *testing.T) {
	enableMail(t)
	bundleId := "allowance-folder-limited"
	bundle := models.FileBundle{
		Id:                 bundleId,
		Name:               "reports",
		CreationDate:       time.Now().Unix(),
		DownloadsRemaining: 2,
		ExpireAt:           time.Now().Add(24 * time.Hour).Unix(),
	}
	database.SaveFileBundle(bundle)
	t.Cleanup(func() { database.DeleteFileBundle(bundle) })
	resource := Resource{Type: models.ShareResourceBundle, Id: bundleId, Name: "reports"}

	_, err := GrantAccess(resource, []string{"folder@example.com"}, testActor(1), 0, "https://x.test/")
	test.IsNil(t, err)

	test.IsEqualInt(t, grantedAllowanceOf(t, models.ShareResourceBundle, bundleId), 2)
}

// A file request has no download allowance to inherit, so its grants stay unlimited.
func TestGrantAllowanceStaysUnlimitedForAFileRequest(t *testing.T) {
	enableMail(t)
	requestId := "allowance-request"
	resource := Resource{Type: models.ShareResourceFileRequest, Id: requestId, Name: "send me the labs"}

	_, err := GrantAccess(resource, []string{"request@example.com"}, testActor(1), 0, "https://x.test/")
	test.IsNil(t, err)

	test.IsEqualInt(t, grantedAllowanceOf(t, models.ShareResourceFileRequest, requestId), 0)
}
