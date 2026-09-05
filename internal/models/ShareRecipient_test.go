package models

import (
	"testing"

	"github.com/forceu/gokapi/internal/test"
)

// The owner's one download limit is each recipient's own budget, so a grant carries that number
// and is spent against it alone. When it runs out the recipient is finished with the resource
// immediately - they stop seeing it as well as being refused it (leeway-session-token plan, D24).
// This used to wait out the download window that spending their last one opened, so a broken
// transfer would not cost them the download; that job now belongs to the download session token,
// which is stronger - it is re-checked against the grant on every use and can be revoked
// mid-window, where a bare window bound to nothing but a timestamp could do neither.

func TestShareGrantIsExhaustedCountsAgainstItsOwnAllowance(t *testing.T) {
	grant := ShareGrant{DownloadsAllowed: 3, DownloadsUsed: 2}
	test.IsEqualBool(t, grant.IsExhausted(1000, 0), false)

	grant.DownloadsUsed = 3
	test.IsEqualBool(t, grant.IsExhausted(1000, 0), true)
}

// An allowance of 0 is unlimited, which is what a grant on a resource that has no download limit
// of its own is written with.
func TestShareGrantIsNeverExhaustedWhenUnlimited(t *testing.T) {
	grant := ShareGrant{DownloadsAllowed: 0, DownloadsUsed: 99}
	test.IsEqualBool(t, grant.IsExhausted(1000, 0), false)
}

// TestShareGrantIsExhaustedImmediatelyRegardlessOfLeeway used to be
// TestShareGrantKeepsAccessUntilItsWindowCloses, and asserted the opposite: that the recipient
// kept their access for the leeway after their last download, and lost it only once that window
// closed. That expectation was deliberately inverted (D24) - a spent recipient is refused the
// instant they are spent, and leeway no longer buys them anything here, however large it is.
func TestShareGrantIsExhaustedImmediatelyRegardlessOfLeeway(t *testing.T) {
	grant := ShareGrant{DownloadsAllowed: 2, DownloadsUsed: 2, LastDownloadAt: 1000}

	test.IsEqualBool(t, grant.IsExhausted(1000, 3600), true)
	test.IsEqualBool(t, grant.IsExhausted(4599, 3600), true)
	test.IsEqualBool(t, grant.IsExhausted(4600, 3600), true)
}

// TestDownloadAccessWithShareGrantsSumsWhatTheRecipientsHaveLeft is the resource-level fold of the
// same numbers: three people with three downloads each leave nine on a file the owner limited to
// three, and the file is not exhausted until the last of them is.
func TestDownloadAccessWithShareGrantsSumsWhatTheRecipientsHaveLeft(t *testing.T) {
	file := File{DownloadsRemaining: 3, UnlimitedTime: true}
	grants := []ShareGrant{
		{RecipientId: 1, DownloadsAllowed: 3, DownloadsUsed: 0},
		{RecipientId: 2, DownloadsAllowed: 3, DownloadsUsed: 0},
		{RecipientId: 3, DownloadsAllowed: 3, DownloadsUsed: 0},
	}

	access := file.DownloadAccess(0).WithShareGrants(grants)
	test.IsEqualInt(t, access.DownloadsRemaining, 9)
	test.IsEqualBool(t, access.UnlimitedDownloads, false)
	test.IsEqualBool(t, access.SpendsOwnCounter, false)
	test.IsEqualBool(t, access.IsExhausted(1000), false)

	// Eight of the nine taken, and one recipient still holds the file open.
	grants[0].DownloadsUsed = 3
	grants[1].DownloadsUsed = 3
	grants[2].DownloadsUsed = 2
	access = file.DownloadAccess(0).WithShareGrants(grants)
	test.IsEqualInt(t, access.DownloadsRemaining, 1)
	test.IsEqualBool(t, access.IsExhausted(1000), false)

	// The ninth ends it.
	grants[2].DownloadsUsed = 3
	access = file.DownloadAccess(0).WithShareGrants(grants)
	test.IsEqualInt(t, access.DownloadsRemaining, 0)
	test.IsEqualBool(t, access.IsExhausted(1000), true)
}

// One recipient with no cap keeps the resource alive however much everyone else has taken, and
// the most recent window any of them opened is the one that holds it.
func TestDownloadAccessWithShareGrantsTakesTheUnlimitedAndTheLatestWindow(t *testing.T) {
	file := File{DownloadsRemaining: 1, UnlimitedTime: true}

	access := file.DownloadAccess(0).WithShareGrants([]ShareGrant{
		{RecipientId: 1, DownloadsAllowed: 1, DownloadsUsed: 1, LastDownloadAt: 500},
		{RecipientId: 2, DownloadsAllowed: 0, DownloadsUsed: 40, LastDownloadAt: 900},
	})
	test.IsEqualBool(t, access.UnlimitedDownloads, true)
	test.IsEqualInt(t, int(access.WindowOpenedAt), 900)
	test.IsEqualBool(t, access.IsExhausted(1000), false)
}
