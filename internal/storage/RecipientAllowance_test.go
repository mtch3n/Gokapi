//go:build !integration && test

package storage

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/test"
)

// This file tests what the owner's download limit means once a file is shared with named
// recipients: it is EACH recipient's budget, not a pool they share. A file limited to three
// downloads and shared with three people is nine downloads, three per person.
//
// Two rules follow, and both are resolved in one place, downloadAccessOf, rather than branched on
// at each call site. Access: the per-recipient grant is the gate and the file's own counter no
// longer meters a recipient's download, the same precedence models.File.AccessMode already gives
// a recipient list over a passcode. Lifetime: the file is exhausted, and so disposable, once the
// last recipient has spent their last download and the window that spending it opened has closed
// - or once it expires, whichever comes first. Nothing else ends it, so a recipient who never
// collects keeps the file alive until its expiry.
//
// Named to sort after FileServing_test.go, for the reason MetadataRetention_test.go explains:
// the tests here run CleanUp over the whole database.

// shareFileWith stores a file with its own download limit and shares it with one grant per
// address, each carrying the same per-recipient allowance. Returns the recipient ids in the order
// the addresses were given.
func shareFileWith(t *testing.T, fileId string, downloadsRemaining int, perRecipientAllowance int, emails ...string) []int {
	t.Helper()
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "shared.txt",
		SHA1:               writeBlob(t, "shared with named recipients"),
		ContentType:        "text/plain",
		Size:               "28 B",
		SizeBytes:          28,
		DownloadsRemaining: downloadsRemaining,
		UnlimitedTime:      true,
	})
	recipientIds := make([]int, 0, len(emails))
	for _, email := range emails {
		recipient, exists := database.GetShareRecipientByEmail(email)
		if !exists {
			recipient = models.ShareRecipient{Email: email, CreatedAt: time.Now().Unix()}
			recipient.Id = database.SaveShareRecipient(recipient)
		}
		recipientIds = append(recipientIds, recipient.Id)
	}
	database.SetShareGrants(models.ShareResourceFile, fileId, recipientIds, 1, perRecipientAllowance)
	t.Cleanup(func() { database.DeleteShareGrants(models.ShareResourceFile, fileId) })
	return recipientIds
}

// downloadAsRecipient runs the two steps webserver.serveFile runs for a recipient, in the order it
// runs them: the recipient's own grant is spent first, then the file is served with the counter
// increase and the expiry recheck the handler asks for. It reports whether the download was
// delivered.
func downloadAsRecipient(t *testing.T, fileId string, recipientId int) bool {
	t.Helper()
	file, ok := GetFile(fileId)
	if !ok {
		return false
	}
	if shareaccess.ConsumeDownload(models.ShareResourceFile, fileId, recipientId, int64(LeewayFor(file).Seconds())) != nil {
		return false
	}
	return ServeFile(file, httptest.NewRecorder(), httptest.NewRequest("GET", "/"+fileId, nil), true, true, false, true)
}

// downloadAnonymously runs what an ordinary link download does, with no recipient involved.
func downloadAnonymously(t *testing.T, fileId string) bool {
	t.Helper()
	file, ok := GetFile(fileId)
	if !ok {
		return false
	}
	return ServeFile(file, httptest.NewRecorder(), httptest.NewRequest("GET", "/"+fileId, nil), true, true, false, true)
}

// TestEveryRecipientGetsTheOwnersWholeAllowance is the owner's example: a file set to three
// downloads and shared with three people is nine downloads. Before the recipient list superseded
// the file's own counter, the file locked itself after the third download in total and the two
// recipients who had taken nothing were refused.
func TestEveryRecipientGetsTheOwnersWholeAllowance(t *testing.T) {
	fileId := "perrecipient_all_" + helper.GenerateRandomString(8)
	recipients := shareFileWith(t, fileId, 3, 3,
		"a-all@example.com", "b-all@example.com", "c-all@example.com")

	delivered := 0
	for round := 0; round < 3; round++ {
		for _, recipientId := range recipients {
			if downloadAsRecipient(t, fileId, recipientId) {
				delivered = delivered + 1
			}
		}
	}
	test.IsEqualInt(t, delivered, 9)

	// The tenth is refused, whoever asks for it.
	for _, recipientId := range recipients {
		test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipientId), false)
	}
}

// TestOneRecipientExhaustingLeavesTheOthersUntouched is the same rule from the other side: the
// budgets are independent, so the first recipient spending all of theirs first takes nothing away
// from the second.
func TestOneRecipientExhaustingLeavesTheOthersUntouched(t *testing.T) {
	fileId := "perrecipient_independent_" + helper.GenerateRandomString(8)
	recipients := shareFileWith(t, fileId, 3, 3,
		"a-independent@example.com", "b-independent@example.com")

	for round := 0; round < 3; round++ {
		test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[0]), true)
	}
	test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[0]), false)

	// The second recipient still has their whole allowance, untouched by the first.
	for round := 0; round < 3; round++ {
		test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[1]), true)
	}
	test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[1]), false)
}

// TestFileWithoutRecipientsIsStillGatedByItsOwnCounter is the regression guard: with nobody named
// on the share there is nothing to defer to, so the file's own allowance meters link downloads
// exactly as it always did.
func TestFileWithoutRecipientsIsStillGatedByItsOwnCounter(t *testing.T) {
	fileId := "perrecipient_link_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "link.txt",
		SHA1:               writeBlob(t, "link only"),
		ContentType:        "text/plain",
		Size:               "9 B",
		SizeBytes:          9,
		DownloadsRemaining: 3,
		UnlimitedTime:      true,
	})

	for round := 0; round < 3; round++ {
		test.IsEqualBool(t, downloadAnonymously(t, fileId), true)
	}
	test.IsEqualBool(t, downloadAnonymously(t, fileId), false)

	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 0)
	test.IsEqualInt(t, stored.DownloadCount, 3)
}

// TestRecipientDownloadsLeaveTheFilesOwnCounterAlone pins the mechanism the two tests above rely
// on: a recipient's download spends their grant and nothing else, so the owner's number stays
// what they typed rather than counting down towards a cap that was never meant to apply.
func TestRecipientDownloadsLeaveTheFilesOwnCounterAlone(t *testing.T) {
	fileId := "perrecipient_counter_" + helper.GenerateRandomString(8)
	recipients := shareFileWith(t, fileId, 3, 3, "a-counter@example.com")

	test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[0]), true)

	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 3)
	test.IsEqualInt(t, stored.DownloadCount, 1)

	grants := database.GetShareGrants(models.ShareResourceFile, fileId)
	test.IsEqualInt(t, len(grants), 1)
	test.IsEqualInt(t, grants[0].DownloadsUsed, 1)
	test.IsEqualInt(t, grants[0].DownloadsAllowed, 3)
}

// --- Lifetime: when is an identity-restricted file exhausted, and so disposable ---

// TestCleanUpDisposesFileOnceEveryRecipientIsSpent is the answer: the last recipient's last
// download is what ends it, not the third download overall.
func TestCleanUpDisposesFileOnceEveryRecipientIsSpent(t *testing.T) {
	setRetention(t, "24h")
	fileId := "perrecipient_spent_" + helper.GenerateRandomString(8)
	recipients := shareFileWith(t, fileId, 3, 3,
		"a-spent@example.com", "b-spent@example.com", "c-spent@example.com")

	for round := 0; round < 3; round++ {
		for _, recipientId := range recipients {
			test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipientId), true)
		}
	}

	CleanUp(false)

	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonDownloaded)
}

// TestCleanUpKeepsFileWhileOneRecipientHasBudget is the half that the file-wide counter used to
// get wrong in the other direction: eight of the nine downloads are gone, but one recipient still
// has one, so the content has to stay.
func TestCleanUpKeepsFileWhileOneRecipientHasBudget(t *testing.T) {
	setRetention(t, "24h")
	fileId := "perrecipient_partial_" + helper.GenerateRandomString(8)
	recipients := shareFileWith(t, fileId, 3, 3,
		"a-partial@example.com", "b-partial@example.com", "c-partial@example.com")

	delivered := 0
	for round := 0; round < 3; round++ {
		for _, recipientId := range recipients {
			if delivered == 8 {
				break
			}
			test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipientId), true)
			delivered = delivered + 1
		}
	}
	test.IsEqualInt(t, delivered, 8)

	CleanUp(false)

	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), false)

	// And that last download is still there to be taken.
	test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[2]), true)
}

// TestCleanUpKeepsFileForARecipientWhoNeverDownloads is the deliberate consequence of the rule:
// somebody who has not collected yet keeps the file alive until it expires, because being able to
// collect it is the whole point of having been sent it. The expiry is what finally ends it, and
// the reason recorded is the expiry rather than the downloads.
func TestCleanUpKeepsFileForARecipientWhoNeverDownloads(t *testing.T) {
	setRetention(t, "24h")
	fileId := "perrecipient_waiting_" + helper.GenerateRandomString(8)
	recipients := shareFileWith(t, fileId, 3, 3,
		"a-waiting@example.com", "b-waiting@example.com", "c-waiting@example.com")

	// The first two collect everything they were given; the third never appears.
	for round := 0; round < 3; round++ {
		test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[0]), true)
		test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[1]), true)
	}

	CleanUp(false)
	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), false)

	// Once the file's own expiry passes, it goes, with the third recipient's budget unspent.
	stored.UnlimitedTime = false
	stored.ExpireAt = time.Now().Add(-time.Hour).Unix()
	database.SaveMetaData(stored)

	CleanUp(false)
	stored, ok = database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonExpired)
}

// TestCleanUpDisposesExpiredFileBeforeAnyoneIsExhausted is the other side of "whichever comes
// first": nobody has spent anything, and the expiry ends it anyway.
func TestCleanUpDisposesExpiredFileBeforeAnyoneIsExhausted(t *testing.T) {
	setRetention(t, "24h")
	fileId := "perrecipient_expired_" + helper.GenerateRandomString(8)
	shareFileWith(t, fileId, 3, 3, "a-expired@example.com", "b-expired@example.com")

	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	stored.UnlimitedTime = false
	stored.ExpireAt = time.Now().Add(-time.Hour).Unix()
	database.SaveMetaData(stored)

	CleanUp(false)

	stored, ok = database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonExpired)
}

// TestCleanUpWaitsForTheLastRecipientsWindow keeps the identity case on the same lifetime rule as
// everything else: the leeway exists so a broken transfer does not cost someone their download,
// so the last recipient's last download opens a window like any other and the file is not
// disposed of while it is still open. The recipient whose window is open here is deliberately not
// the one who downloaded first, which is what makes this the LAST window rather than any window.
//
// The file's own counter is left in exactly the state that would end a link-only file - spent,
// its own window long closed - to prove it plays no part once the file has recipients.
func TestCleanUpWaitsForTheLastRecipientsWindow(t *testing.T) {
	setRetention(t, "24h")
	setDownloadLeeway(t, "1h")
	fileId := "perrecipient_window_" + helper.GenerateRandomString(8)
	recipients := shareFileWith(t, fileId, 0, 1,
		"a-window@example.com", "b-window@example.com")
	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	stored.WindowOpenedAt = time.Now().Add(-2 * time.Hour).Unix()
	database.SaveMetaData(stored)

	// Spending with an explicit timestamp is how a window that opened in the past is set up:
	// the first recipient collected two hours ago, the second just now.
	granted, opened := database.AcquireShareGrantDownload(models.ShareResourceFile, fileId,
		recipients[0], time.Now().Add(-2*time.Hour).Unix(), 3600)
	test.IsEqualBool(t, granted, true)
	test.IsEqualBool(t, opened, true)
	granted, opened = database.AcquireShareGrantDownload(models.ShareResourceFile, fileId,
		recipients[1], time.Now().Unix(), 3600)
	test.IsEqualBool(t, granted, true)
	test.IsEqualBool(t, opened, true)

	CleanUp(false)
	stored, ok = database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), false)
	test.FileExists(t, configuration.Get().DataDir+"/"+stored.SHA1)

	// The second recipient's own retry is still free while that window is open, which is what the
	// window is for.
	test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[1]), true)
}

// TestCleanUpDisposesOnceTheLastWindowClosed is the closing half of the test above, with the
// file's own counter left the other way round - four of its five downloads still unspent - so
// that what ends the file can only be the recipients having finished.
func TestCleanUpDisposesOnceTheLastWindowClosed(t *testing.T) {
	setRetention(t, "24h")
	setDownloadLeeway(t, "1h")
	fileId := "perrecipient_windowclosed_" + helper.GenerateRandomString(8)
	recipients := shareFileWith(t, fileId, 5, 1,
		"a-windowclosed@example.com", "b-windowclosed@example.com")

	for _, recipientId := range recipients {
		granted, opened := database.AcquireShareGrantDownload(models.ShareResourceFile, fileId,
			recipientId, time.Now().Add(-2*time.Hour).Unix(), 3600)
		test.IsEqualBool(t, granted, true)
		test.IsEqualBool(t, opened, true)
	}

	CleanUp(false)

	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonDownloaded)
}

// TestUnlimitedGrantKeepsTheFileAlive is the unlimited end of the fold: one recipient with no cap
// means the file is never exhausted, however much everyone else has taken.
func TestUnlimitedGrantKeepsTheFileAlive(t *testing.T) {
	setRetention(t, "24h")
	fileId := "perrecipient_unlimited_" + helper.GenerateRandomString(8)
	recipients := shareFileWith(t, fileId, 1, 0, "a-unlimited@example.com")

	for round := 0; round < 4; round++ {
		test.IsEqualBool(t, downloadAsRecipient(t, fileId, recipients[0]), true)
	}

	CleanUp(false)

	stored, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), false)
}
