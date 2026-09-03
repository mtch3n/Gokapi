package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/test"
)

// A recipient who has spent their own allowance is finished with the share and stops seeing it
// at all, while every other recipient carries on with their own budget untouched. The inbox
// filter for that already existed but could never fire: every grant was written with an allowance
// of 0, which means unlimited, so nothing was ever spent in full.

// inboxOf lists what one address currently sees in their inbox.
func inboxOf(t *testing.T, userId int, email string) shareInboxResponseTest {
	t.Helper()
	w := httptest.NewRecorder()
	apiShareInbox(w, nil, models.User{Id: userId, Name: email}, models.ApiKey{})
	var response shareInboxResponseTest
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &response))
	return response
}

// TestApiShareInboxHidesTheShareOnlyFromTheSpentRecipient is the visibility half of the
// per-recipient allowance: the owner's three downloads are three each, so the recipient who has
// taken all three loses the share while the one who has taken none still holds it.
//
// The share is created the way the product creates it - through shareaccess.GrantAccess with no
// allowance of its own - because that is what used to store 0, leave every grant unlimited, and
// keep an exhausted recipient looking at a share they could no longer open.
func TestApiShareInboxHidesTheShareOnlyFromTheSpentRecipient(t *testing.T) {
	enableMail(t)
	fileId := "inboxPerRecipient"
	database.SaveMetaData(models.File{
		Id: fileId, Name: "per-recipient.txt", SHA1: "inboxshaperrecipient",
		DownloadsRemaining: 3, UnlimitedTime: true, UserId: idAdmin,
	})
	t.Cleanup(func() { database.DeleteMetaData(fileId) })

	spentEmail := "inbox-perrecipient-a@example.com"
	waitingEmail := "inbox-perrecipient-b@example.com"
	resource := shareaccess.Resource{Type: models.ShareResourceFile, Id: fileId, Name: "per-recipient.txt"}
	_, err := shareaccess.GrantAccess(resource, []string{spentEmail, waitingEmail},
		models.User{Id: idAdmin, Name: "admin"}, 0, "https://x.test/")
	test.IsNil(t, err)
	t.Cleanup(func() { database.DeleteShareGrants(models.ShareResourceFile, fileId) })

	spent, found := database.GetShareRecipientByEmail(spentEmail)
	test.IsEqualBool(t, found, true)

	// Both see it to begin with.
	test.IsEqualInt(t, len(inboxOf(t, 5101, spentEmail).Items), 1)
	test.IsEqualInt(t, len(inboxOf(t, 5102, waitingEmail).Items), 1)

	// The first recipient takes all three of the downloads the owner set. Leeway 0, so each
	// window closes at once and the third leaves them genuinely finished.
	for round := 0; round < 3; round++ {
		granted, _ := database.AcquireShareGrantDownload(models.ShareResourceFile, fileId,
			spent.Id, time.Now().Unix(), 0)
		test.IsEqualBool(t, granted, true)
	}

	test.IsEqualInt(t, len(inboxOf(t, 5101, spentEmail).Items), 0)

	// The second recipient is completely unaffected, and still has the owner's whole number.
	waiting := inboxOf(t, 5102, waitingEmail)
	test.IsEqualInt(t, len(waiting.Items), 1)
	test.IsEqualString(t, waiting.Items[0].ResourceId, fileId)
}
