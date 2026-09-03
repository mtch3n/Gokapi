package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
)

// TestFolderListPublishesStatusAndAllowance covers the folder list's four new fields, and in
// particular the one case a client could never get right on its own: a folder restricted to named
// recipients keeps its OWN downloadsremaining frozen at whatever the owner set, so the raw counter
// says nothing about whether the folder is spent. allowanceremaining carries the sum of what its
// recipients still have, and status follows that rather than the frozen row.
func TestFolderListPublishesStatusAndAllowance(t *testing.T) {
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermView)
	database.SaveApiKey(apiKey)

	live := filebundle.Create("allowance-live", idUser)
	live.UnlimitedDownloads = false
	live.DownloadsRemaining = 4
	database.SaveFileBundle(live)

	// Spent and unshared: the package's test leeway is 0, so no window keeps it alive.
	spent := filebundle.Create("allowance-spent", idUser)
	spent.UnlimitedDownloads = false
	spent.DownloadsRemaining = 0
	database.SaveFileBundle(spent)

	// Own counter spent, but its recipients still hold budget, so the folder is NOT exhausted.
	// The second SetShareGrants call is deliberate: it re-sets the list to both recipients with
	// an allowance of 3, and A KEEPS the 2 it was already granted rather than being re-issued at
	// 3 (grants survive a list edit). The sum is therefore 2+3, which is also a small guard that
	// allowanceremaining is read from the grant rows rather than recomputed from the folder.
	shared := filebundle.Create("allowance-shared", idUser)
	shared.UnlimitedDownloads = false
	shared.DownloadsRemaining = 0
	database.SaveFileBundle(shared)
	recipientA := database.SaveShareRecipient(models.ShareRecipient{
		Email: "allowance-a-" + helper.GenerateRandomString(6) + "@example.com"})
	recipientB := database.SaveShareRecipient(models.ShareRecipient{
		Email: "allowance-b-" + helper.GenerateRandomString(6) + "@example.com"})
	database.SetShareGrants(models.ShareResourceBundle, shared.Id,
		[]int{recipientA}, idUser, 2)
	database.SetShareGrants(models.ShareResourceBundle, shared.Id,
		[]int{recipientA, recipientB}, idUser, 3)

	deleted := filebundle.Create("allowance-deleted", idUser)
	deleted.DeletedAt = 1
	database.SaveFileBundle(deleted)

	t.Cleanup(func() {
		for _, b := range []models.FileBundle{live, spent, shared, deleted} {
			database.DeleteFileBundle(models.FileBundle{Id: b.Id})
		}
	})

	w, r := getRecorder("/folder/list", apiKey.Id, []test.Header{})
	Process(w, r)
	test.IsEqualInt(t, w.Code, http.StatusOK)

	var listed []struct {
		Id                 string `json:"id"`
		Status             string `json:"status"`
		DownloadsRemaining int    `json:"downloadsremaining"`
		AllowanceGoverning string `json:"allowancegoverning"`
		AllowanceRemaining int    `json:"allowanceremaining"`
		AllowanceUnlimited bool   `json:"allowanceunlimited"`
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &listed))

	seen := 0
	for _, item := range listed {
		switch item.Id {
		case live.Id:
			seen++
			test.IsEqualString(t, item.Status, models.StatusActive)
			test.IsEqualString(t, item.AllowanceGoverning, models.AllowanceGoverningOwn)
			test.IsEqualInt(t, item.AllowanceRemaining, 4)
			test.IsEqualBool(t, item.AllowanceUnlimited, false)
		case spent.Id:
			seen++
			test.IsEqualString(t, item.Status, models.StatusDownloaded)
			test.IsEqualString(t, item.AllowanceGoverning, models.AllowanceGoverningOwn)
			test.IsEqualInt(t, item.AllowanceRemaining, 0)
		case shared.Id:
			seen++
			// The whole point: the raw counter reads 0 and the folder is still live.
			test.IsEqualInt(t, item.DownloadsRemaining, 0)
			test.IsEqualString(t, item.AllowanceGoverning, models.AllowanceGoverningRecipients)
			test.IsEqualInt(t, item.AllowanceRemaining, 5)
			test.IsEqualString(t, item.Status, models.StatusActive)
		case deleted.Id:
			seen++
			test.IsEqualString(t, item.Status, models.StatusDeleted)
		}
	}
	test.IsEqualInt(t, seen, 4)
}
