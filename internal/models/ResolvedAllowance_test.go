package models

import (
	"testing"

	"github.com/forceu/gokapi/internal/test"
)

// TestDownloadAccessGoverningAgreesWithSpendsOwnCounter pins the two fields to the same fact.
// Governing is the read side of what SpendsOwnCounter decides on the write side, so exactly one
// value of Governing may permit spending the resource's own row. Kept as a test rather than
// collapsing the two into one field: SpendsOwnCounter is checked on the hot download path and
// wants to stay a bool, while a client needs to know WHICH other counter governs, which a bool
// cannot say.
func TestDownloadAccessGoverningAgreesWithSpendsOwnCounter(t *testing.T) {
	own := (&File{DownloadsRemaining: 3}).DownloadAccess(0)
	test.IsEqualString(t, own.Governing, AllowanceGoverningOwn)
	test.IsEqualBool(t, own.SpendsOwnCounter, true)

	byRecipients := own.WithShareGrants([]ShareGrant{{DownloadsAllowed: 2}})
	test.IsEqualString(t, byRecipients.Governing, AllowanceGoverningRecipients)
	test.IsEqualBool(t, byRecipients.SpendsOwnCounter, false)

	byFolder := (&FileBundle{DownloadsRemaining: 5}).DownloadAccess(0)
	test.IsEqualString(t, byFolder.Governing, AllowanceGoverningOwn)
	test.IsEqualBool(t, byFolder.SpendsOwnCounter, true)
}

// TestToFileApiOutputPublishesResolvedAllowance is the whole point of the three Allowance fields:
// a file governed by its recipients keeps its OWN counter frozen at whatever the owner set, so a
// client reading DownloadsRemaining to decide whether the file is spent is wrong for exactly the
// files that were shared. Both numbers go out, and they deliberately disagree here - 3 is what the
// owner set, 4 is what the two recipients between them still have.
func TestToFileApiOutputPublishesResolvedAllowance(t *testing.T) {
	file := File{
		Id: "allowanceTestId", Name: "allowance.txt", DownloadsRemaining: 3, UnlimitedTime: true,
	}
	access := file.DownloadAccess(0).WithShareGrants([]ShareGrant{
		{DownloadsAllowed: 3, DownloadsUsed: 1},
		{DownloadsAllowed: 3, DownloadsUsed: 1},
	})

	output, err := file.ToFileApiOutput("serverurl/", false, access)
	test.IsNil(t, err)
	test.IsEqualString(t, output.AllowanceGoverning, AllowanceGoverningRecipients)
	test.IsEqualInt(t, output.AllowanceRemaining, 4)
	test.IsEqualBool(t, output.AllowanceUnlimited, false)
	// The owner's own number survives untouched beside it - the edit dialog and the "n of m"
	// denominator are about what was set, not about what is left.
	test.IsEqualInt(t, output.DownloadsRemaining, 3)
}

// TestToFileApiOutputAllowanceUnlimitedFromAnUnlimitedGrant covers the case the frozen own counter
// hides completely: the file itself is limited, but a recipient granted an unlimited budget makes
// the governing allowance unlimited. AllowanceRemaining carries no meaning then, which is why
// AllowanceUnlimited is published rather than left to be inferred from a zero.
func TestToFileApiOutputAllowanceUnlimitedFromAnUnlimitedGrant(t *testing.T) {
	file := File{Id: "allowanceUnlimitedId", Name: "u.txt", DownloadsRemaining: 2, UnlimitedTime: true}
	access := file.DownloadAccess(0).WithShareGrants([]ShareGrant{{DownloadsAllowed: 0}})

	output, err := file.ToFileApiOutput("serverurl/", false, access)
	test.IsNil(t, err)
	test.IsEqualString(t, output.AllowanceGoverning, AllowanceGoverningRecipients)
	test.IsEqualBool(t, output.AllowanceUnlimited, true)
	test.IsEqualInt(t, output.DownloadsRemaining, 2)
}
