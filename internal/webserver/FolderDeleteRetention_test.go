//go:build !integration && test

package webserver

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
)

// A deleted folder keeps its row while its members keep theirs, so that the file list still has a
// folder to group them under (see models.FileBundle.DeletedAt). That row must never let anyone back
// in, and the two tests here cover both ends of the window it exists for: the moment the folder is
// deleted, and the whole retention period it lingers for afterwards.

// TestDeletedFolderLinkIsRefusedAtOnce drives the real delete path. Nothing has been swept yet at
// the point the second request is made - the members are only marked for deletion, their content is
// still on disk - and the link must already be dead.
func TestDeletedFolderLinkIsRefusedAtOnce(t *testing.T) {
	bundle := filebundle.Create("TestDeletedFolder_Immediate", 5)
	memberId := "deletedfolder_immediate_" + helper.GenerateRandomString(8)
	// Its own blob, not one of the shared fixture blobs: this is the only test in the package that
	// disposes of a member for real, and disposal deletes the content unless another live row still
	// references it.
	sha1 := "deletedfolder_immediate_blob_" + helper.GenerateRandomString(8)
	err := os.WriteFile(configuration.Get().DataDir+"/"+sha1, []byte("789"), 0600)
	test.IsNil(t, err)
	database.SaveMetaData(models.File{
		Id:                 memberId,
		Name:               "immediate.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               sha1,
		ContentType:        "text/plain",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             5,
		BundleId:           bundle.Id,
	})
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundle.Id})
	})

	client := &http.Client{}

	// The folder really is servable first, or a 404 below would prove nothing.
	beforeResp, err := client.Get(urlIp + "/pubapi/folder?id=" + bundle.Id)
	if err != nil {
		t.Fatalf("Failed to request folder: %v", err)
	}
	defer beforeResp.Body.Close()
	if beforeResp.StatusCode != http.StatusOK {
		t.Errorf("Expected the folder to be servable before it is deleted, got status %d", beforeResp.StatusCode)
	}

	filebundle.Delete(bundle)

	afterResp, err := client.Get(urlIp + "/pubapi/folder?id=" + bundle.Id)
	if err != nil {
		t.Fatalf("Failed to request deleted folder: %v", err)
	}
	defer afterResp.Body.Close()
	afterBody, _ := io.ReadAll(afterResp.Body)

	if afterResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected a deleted folder to answer as not found, got status %d, body %s", afterResp.StatusCode, afterBody)
	}
	if strings.Contains(string(afterBody), "immediate.txt") {
		t.Errorf("Deleted folder leaked a member name: %s", afterBody)
	}
}

// TestDeletedFolderLinkIsRefusedWhileItsRowRemains covers the rest of that window, where the folder
// row is deliberately still in the database with its disposed members alongside it. The state is
// written directly rather than reached through filebundle.Delete and a wait: this suite runs with
// GOKAPI_METADATA_RETENTION at 0, under which the background sweep collects both within
// milliseconds, so driving it would leave the assertion racing that sweep instead of testing
// anything. That the delete path really does leave exactly this state is what
// TestDeleteKeepsFolderWhileItsDeletedFilesRemain covers, in the filebundle package.
func TestDeletedFolderLinkIsRefusedWhileItsRowRemains(t *testing.T) {
	// The member row is written before the folder is marked, never after: a folder marked deleted
	// with no member row yet is a folder with nothing keeping it, and any sweep running in the
	// background would collect it - correctly - out from under the fixture.
	bundle := filebundle.Create("TestDeletedFolder_Retained", 5)
	memberId := "deletedfolder_retained_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 memberId,
		Name:               "retained.txt",
		Size:               "3 B",
		SizeBytes:          3,
		ContentType:        "text/plain",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             5,
		BundleId:           bundle.Id,
		DisposedAt:         time.Now().Add(-time.Minute).Unix(),
		DisposalReason:     models.DisposalReasonDeleted,
	})
	bundle.DeletedAt = time.Now().Add(-time.Minute).Unix()
	database.SaveFileBundle(bundle)
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundle.Id})
	})

	client := &http.Client{}

	folderResp, err := client.Get(urlIp + "/pubapi/folder?id=" + bundle.Id)
	if err != nil {
		t.Fatalf("Failed to request folder: %v", err)
	}
	defer folderResp.Body.Close()
	folderBody, _ := io.ReadAll(folderResp.Body)

	if folderResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected a retained deleted folder to answer as not found, got status %d, body %s", folderResp.StatusCode, folderBody)
	}
	if strings.Contains(string(folderBody), "retained.txt") {
		t.Errorf("Retained deleted folder leaked a member name: %s", folderBody)
	}

	zipResp, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle.Id)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	defer zipResp.Body.Close()
	zipBody, _ := io.ReadAll(zipResp.Body)

	if zipResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected the zip of a retained deleted folder to answer as not found, got status %d", zipResp.StatusCode)
	}
	if len(zipBody) > 0 && zipResp.Header.Get("Content-Disposition") != "" {
		t.Errorf("Retained deleted folder served bytes, Content-Type=%s Content-Disposition=%s",
			zipResp.Header.Get("Content-Type"), zipResp.Header.Get("Content-Disposition"))
	}

	// The refusals above are what a row that is still there answers with, not what a missing row
	// answers with - so the row has to still be there for them to have meant anything.
	stored, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.DeletedAt != 0, true)
	member, ok := database.GetMetaDataById(memberId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, member.BundleId, bundle.Id)
}
