package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
)

// TestShareRecipientsRefusedOnDeletedFolder pins that a deleted folder cannot be shared with
// anyone new. It is refused directly on the folder's deleted state rather than by inheriting the
// no-live-members check next to it: that check only refuses a deleted folder for as long as a
// deleted folder cannot regain a live member, which is a promise kept by an upload guard in a
// different file. Granting access is the one call here that hands out new reach, so it must not
// depend on a guarantee made somewhere else.
func TestShareRecipientsRefusedOnDeletedFolder(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermEdit)
	database.SaveApiKey(apiKey)

	bundle := filebundle.Create("deleted-folder-share", idUser)
	memberId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id: memberId, Name: "member.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		Size: "3 B", SizeBytes: 3, UserId: idUser, BundleId: bundle.Id,
		ExpireAt: time.Now().Add(72 * time.Hour).Unix(), DownloadsRemaining: 1,
	})
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundle.Id})
	})

	// While the folder is live the call gets PAST resolveShareResource and only then fails on
	// the test instance having no mail connector (412). That is the control: it proves the 404
	// below comes from the folder being deleted and not from the fixture being unshareable to
	// begin with, which a bare "expect 404" test could never distinguish.
	w, r := getRecorderWithBody("/api/share/recipients", apiKey.Id, "POST",
		[]test.Header{{Name: "Content-Type", Value: "application/json"}},
		strings.NewReader(`{"resourceType":1,"resourceId":"`+bundle.Id+`","emails":["live@example.test"],"downloadsAllowed":0}`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, http.StatusPreconditionFailed)

	// Mark it deleted the way filebundle.Delete does, but leave the member row live, so the
	// no-live-members check cannot be what refuses the call.
	stored, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, true)
	stored.DeletedAt = time.Now().Unix()
	database.SaveFileBundle(stored)

	w, r = getRecorderWithBody("/api/share/recipients", apiKey.Id, "POST",
		[]test.Header{{Name: "Content-Type", Value: "application/json"}},
		strings.NewReader(`{"resourceType":1,"resourceId":"`+bundle.Id+`","emails":["after@example.test"],"downloadsAllowed":0}`))
	Process(w, r)
	test.IsEqualInt(t, w.Code, http.StatusNotFound)
}
