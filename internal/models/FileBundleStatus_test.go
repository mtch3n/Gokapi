package models

import (
	"testing"

	"github.com/forceu/gokapi/internal/test"
)

// TestFileBundleStatusDeletedWinsOverEverything pins the order of the tests in FileBundle.Status.
// A deleted folder keeps its row while its disposed members keep theirs, and such a row is
// typically ALSO expired or exhausted by then - so if deletion were not tested first, the owner
// would be told their folder expired when in fact they deleted it.
func TestFileBundleStatusDeletedWinsOverEverything(t *testing.T) {
	bundle := FileBundle{DeletedAt: 500, ExpireAt: 100, DownloadsRemaining: 0}
	test.IsEqualString(t, bundle.Status(bundle.DownloadAccess(0), 1000), StatusDeleted)
}

// TestFileBundleStatusFollowsTheGoverningAllowance is the folder half of the reason the Allowance
// fields exist: a folder restricted to named recipients is NOT exhausted while any recipient still
// has budget, however spent its own frozen counter reads. Status has to follow the access it is
// given rather than the folder's own row, or a shared folder would be reported downloaded while
// every recipient could still collect it.
func TestFileBundleStatusFollowsTheGoverningAllowance(t *testing.T) {
	bundle := FileBundle{DownloadsRemaining: 0, UnlimitedTime: true}

	// Its own spent counter governs: exhausted.
	test.IsEqualString(t, bundle.Status(bundle.DownloadAccess(0), 1000), StatusDownloaded)

	// Its recipients govern, and one of them still has budget: active, despite the same row.
	byRecipients := bundle.DownloadAccess(0).WithShareGrants([]ShareGrant{{DownloadsAllowed: 2}})
	test.IsEqualString(t, bundle.Status(byRecipients, 1000), StatusActive)
	test.IsEqualString(t, byRecipients.Governing, AllowanceGoverningRecipients)
	test.IsEqualInt(t, byRecipients.DownloadsRemaining, 2)
}

// TestFileBundleStatusExpiredBeforeActive covers the remaining branch: a folder with allowance
// left but a past expiry is expired, not active.
func TestFileBundleStatusExpiredBeforeActive(t *testing.T) {
	bundle := FileBundle{DownloadsRemaining: 5, ExpireAt: 100}
	test.IsEqualString(t, bundle.Status(bundle.DownloadAccess(0), 1000), StatusExpired)

	live := FileBundle{DownloadsRemaining: 5, UnlimitedTime: true}
	test.IsEqualString(t, live.Status(live.DownloadAccess(0), 1000), StatusActive)
}

// TestFileBundleStatusActiveWhileAllowanceRemainsEvenWithWindowOpen is the folder twin of the
// negative that matters most for File.Status's IsSpent branch: allowance left means IsSpent is
// false, an open window notwithstanding. The leeway is set explicitly, since the package's zero
// default would close the window at once and prove nothing about this case.
func TestFileBundleStatusActiveWhileAllowanceRemainsEvenWithWindowOpen(t *testing.T) {
	bundle := FileBundle{DownloadsRemaining: 2, UnlimitedTime: true, WindowOpenedAt: 1000}
	test.IsEqualString(t, bundle.Status(bundle.DownloadAccess(3600), 1000), StatusActive)
}

// TestFileBundleStatusPendingDeletionOnlyWhileSpentAndWindowOpen is the folder twin of the same
// test on File: IsSpent is also true once a folder is downloaded or expired, so the branch has to
// sit after IsExhausted and IsExpired in FileBundle.Status or it would swallow both.
func TestFileBundleStatusPendingDeletionOnlyWhileSpentAndWindowOpen(t *testing.T) {
	spentOpen := FileBundle{DownloadsRemaining: 0, UnlimitedTime: true, WindowOpenedAt: 1000}
	test.IsEqualString(t, spentOpen.Status(spentOpen.DownloadAccess(3600), 1000), StatusPendingDeletion)

	spentClosed := FileBundle{DownloadsRemaining: 0, UnlimitedTime: true, WindowOpenedAt: 1000 - 7200}
	test.IsEqualString(t, spentClosed.Status(spentClosed.DownloadAccess(3600), 1000), StatusDownloaded)

	expired := FileBundle{DownloadsRemaining: 0, ExpireAt: 100, WindowOpenedAt: 1000}
	test.IsEqualString(t, expired.Status(expired.DownloadAccess(3600), 1000), StatusExpired)
}

// TestFileBundleStatusUnlimitedDownloadsNeverPendingDeletion pins that IsSpent can never be true
// for an unlimited-downloads folder, so it never reports pending_deletion, whatever the window is
// doing.
func TestFileBundleStatusUnlimitedDownloadsNeverPendingDeletion(t *testing.T) {
	open := FileBundle{UnlimitedDownloads: true, UnlimitedTime: true, WindowOpenedAt: 1000}
	test.IsEqualString(t, open.Status(open.DownloadAccess(3600), 1000), StatusActive)

	closed := FileBundle{UnlimitedDownloads: true, UnlimitedTime: true, WindowOpenedAt: 1000 - 7200}
	test.IsEqualString(t, closed.Status(closed.DownloadAccess(3600), 1000), StatusActive)
}

// TestFileBundleStatusRecipientsAllFinishedIsPendingDeletion extends
// TestFileBundleStatusFollowsTheGoverningAllowance's "one recipient still has budget" case with its
// counterpart: only once every recipient is finished does the summed allowance read spent, and
// only then, with the window still open, does the folder report pending_deletion.
func TestFileBundleStatusRecipientsAllFinishedIsPendingDeletion(t *testing.T) {
	bundle := FileBundle{UnlimitedTime: true}
	allFinished := bundle.DownloadAccess(3600).WithShareGrants([]ShareGrant{
		{DownloadsAllowed: 1, DownloadsUsed: 1, LastDownloadAt: 1000},
		{DownloadsAllowed: 1, DownloadsUsed: 1, LastDownloadAt: 1000},
	})
	test.IsEqualString(t, bundle.Status(allFinished, 1000), StatusPendingDeletion)
}
