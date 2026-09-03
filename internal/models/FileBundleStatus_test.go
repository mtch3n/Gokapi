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
