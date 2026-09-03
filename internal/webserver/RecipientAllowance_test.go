//go:build !integration && test

package webserver

import (
	"net/http"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

// A folder is shared the same way a file is, so the owner's one number is each recipient's own
// budget here too: a folder limited to two visits and shared with two people is four visits, two
// each. The folder's own counter used to meter every recipient together, which stopped the second
// recipient the moment the first had taken the lot.

// folderZipAs requests the whole folder as the holder of one access cookie, and reports the
// status it got.
func folderZipAs(t *testing.T, bundleId string, cookie test.Cookie) int {
	t.Helper()
	client := &http.Client{}
	req, err := http.NewRequest("GET", urlIp+"/pubapi/folderzip?id="+bundleId, nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req.Header.Set("Cookie", cookie.Name+"="+cookie.Value)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestFolderZipGivesEveryRecipientTheOwnersWholeAllowance(t *testing.T) {
	bundleId := "perRecipientFolder" + helper.GenerateRandomString(8)
	database.SaveFileBundle(models.FileBundle{
		Id:                 bundleId,
		Name:               "per-recipient folder",
		UserId:             999,
		CreationDate:       time.Now().Unix(),
		DownloadsRemaining: 2,
		UnlimitedTime:      true,
	})
	memberId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:          memberId,
		Name:        "folder_member.txt",
		Size:        "3 B",
		SizeBytes:   3,
		SHA1:        "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ContentType: "text/plain",
		UserId:      999,
		BundleId:    bundleId,
		ExpireAt:    2147483646,
	})

	first := database.SaveShareRecipient(models.ShareRecipient{
		Email: "folder-allowance-a@example.com", CreatedAt: time.Now().Unix()})
	second := database.SaveShareRecipient(models.ShareRecipient{
		Email: "folder-allowance-b@example.com", CreatedAt: time.Now().Unix()})
	// A third recipient who never collects, and is what this test is measured against rather
	// than a spare. Once EVERY recipient is spent the folder is exhausted and CleanUp may
	// legitimately collect it, so a test that spends them all is racing the sweep for the rows
	// it then asserts on. Leaving one budget unspent keeps the folder alive, which is also the
	// sharper statement: an individual recipient running out is independent of the folder's own
	// life. That the folder dies when the LAST recipient finishes is asserted in
	// storage.TestCleanUpDisposesFileOnceEveryRecipientIsSpent, where no webserver is running.
	third := database.SaveShareRecipient(models.ShareRecipient{
		Email: "folder-allowance-c@example.com", CreatedAt: time.Now().Unix()})
	database.SetShareGrants(models.ShareResourceBundle, bundleId, []int{first, second, third}, 999, 2)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceBundle, bundleId)
		database.DeleteShareRecipient(first)
		database.DeleteShareRecipient(second)
		database.DeleteShareRecipient(third)
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundleId})
	})

	firstCookie := testShareAccessCookie(models.ShareResourceBundle, bundleId, first)
	secondCookie := testShareAccessCookie(models.ShareResourceBundle, bundleId, second)

	// Two visits each, four in all, on a folder the owner limited to two.
	for round := 0; round < 2; round++ {
		test.IsEqualInt(t, folderZipAs(t, bundleId, firstCookie), http.StatusOK)
		test.IsEqualInt(t, folderZipAs(t, bundleId, secondCookie), http.StatusOK)
	}

	// A fifth visit is refused for each of them: they are individually finished, even though the
	// folder is not - the third recipient has never collected and still may.
	test.IsEqualInt(t, folderZipAs(t, bundleId, firstCookie), http.StatusNotFound)
	test.IsEqualInt(t, folderZipAs(t, bundleId, secondCookie), http.StatusNotFound)

	// The folder's own counter was never touched: it is the owner's per-recipient number, not a
	// pool the recipients raced for.
	stored, ok := database.GetFileBundle(bundleId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 2)
}
