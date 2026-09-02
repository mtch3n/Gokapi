package models

import (
	"testing"

	"github.com/forceu/gokapi/internal/test"
)

// TestFileBundlePopulateExcludesDisposedAndPendingMembers is the failing-first test for
// FileBundle.Populate's membercount/totalsizebytes: it used to exclude only
// IsPendingForDeletion, so a disposed member's SizeBytes - never zeroed by disposeFile - stayed
// counted, telling the owner the folder held more bytes, and more files, than it actually did.
// Populate must count only current members (see File.IsBundleMember): here a bundle with one
// active, one disposed and one pending-deletion file must report a count and size reflecting the
// active file alone.
func TestFileBundlePopulateExcludesDisposedAndPendingMembers(t *testing.T) {
	bundle := FileBundle{Id: "populate-test-bundle"}

	activeFile := File{Id: "active", BundleId: bundle.Id, SizeBytes: 50}
	disposedFile := File{Id: "disposed", BundleId: bundle.Id, SizeBytes: 500, DisposedAt: 1758000000}
	pendingFile := File{Id: "pending", BundleId: bundle.Id, SizeBytes: 5000, PendingDeletion: 1758000000}
	otherBundleFile := File{Id: "other-bundle", BundleId: "some-other-bundle", SizeBytes: 99999}

	allFiles := map[string]File{
		activeFile.Id:      activeFile,
		disposedFile.Id:    disposedFile,
		pendingFile.Id:     pendingFile,
		otherBundleFile.Id: otherBundleFile,
	}

	members, totalSize, count := bundle.Populate(allFiles)

	test.IsEqualInt(t, count, 1)
	test.IsEqualInt64(t, totalSize, activeFile.SizeBytes)
	if len(members) != 1 || members[0].Id != activeFile.Id {
		t.Fatalf("expected Populate to return only the active member, got %v", members)
	}
}

// TestDeriveBundleSettingsFromMembersAgree is the simple case: every member already carries the
// same password, expiry and download cap, so the bundle should simply inherit that shared value
// regardless of upload order.
func TestDeriveBundleSettingsFromMembersAgree(t *testing.T) {
	members := []File{
		{Id: "b", UploadDate: 200, PasswordHash: "sharedhash", ExpireAt: 1800000000, DownloadsRemaining: 4},
		{Id: "a", UploadDate: 100, PasswordHash: "sharedhash", ExpireAt: 1800000000, DownloadsRemaining: 4},
	}
	passwordHash, expireAt, unlimitedTime, downloadsRemaining, unlimitedDownloads := DeriveBundleSettingsFromMembers(members)
	test.IsEqualString(t, passwordHash, "sharedhash")
	test.IsEqualInt64(t, expireAt, 1800000000)
	test.IsEqualBool(t, unlimitedTime, false)
	test.IsEqualInt(t, downloadsRemaining, 4)
	test.IsEqualBool(t, unlimitedDownloads, false)
}

// TestDeriveBundleSettingsFromMembersDisagree is Ming's documented migration choice for members
// that disagree: the most restrictive value on each axis wins, not an arbitrary member's and not
// simply the earliest-uploaded one, so the migration can only leave a bundle as-or-less
// accessible than it was. The earliest-uploaded member here is unprotected, has the loosest
// expiry and the largest download cap - if any of those had been picked, the migration would have
// made the bundle MORE accessible than a later, stricter member intended.
func TestDeriveBundleSettingsFromMembersDisagree(t *testing.T) {
	members := []File{
		{Id: "earlier", UploadDate: 50, PasswordHash: "", ExpireAt: 1900000000, DownloadsRemaining: 9},
		{Id: "later", UploadDate: 150, PasswordHash: "laterhash", ExpireAt: 1700000000, DownloadsRemaining: 2},
	}
	passwordHash, expireAt, unlimitedTime, downloadsRemaining, unlimitedDownloads := DeriveBundleSettingsFromMembers(members)
	test.IsEqualString(t, passwordHash, "laterhash")
	test.IsEqualInt64(t, expireAt, 1700000000)
	test.IsEqualBool(t, unlimitedTime, false)
	test.IsEqualInt(t, downloadsRemaining, 2)
	test.IsEqualBool(t, unlimitedDownloads, false)
}

// TestDeriveBundleSettingsFromMembersUnlimitedOnlyIfEveryMemberIs proves UnlimitedTime and
// UnlimitedDownloads only come back true when EVERY member was unlimited on that axis - one
// capped member among unlimited ones must still produce a real, finite value, the same
// most-restrictive-wins rule as the numeric case.
func TestDeriveBundleSettingsFromMembersUnlimitedOnlyIfEveryMemberIs(t *testing.T) {
	members := []File{
		{Id: "unlimited1", UploadDate: 100, UnlimitedTime: true, UnlimitedDownloads: true},
		{Id: "unlimited2", UploadDate: 200, UnlimitedTime: true, UnlimitedDownloads: true},
	}
	_, _, unlimitedTime, _, unlimitedDownloads := DeriveBundleSettingsFromMembers(members)
	test.IsEqualBool(t, unlimitedTime, true)
	test.IsEqualBool(t, unlimitedDownloads, true)

	membersWithOneCapped := append(members, File{
		Id: "capped", UploadDate: 300, UnlimitedTime: false, ExpireAt: 1234567890,
		UnlimitedDownloads: false, DownloadsRemaining: 7,
	})
	_, expireAt, unlimitedTimeMixed, downloadsRemaining, unlimitedDownloadsMixed := DeriveBundleSettingsFromMembers(membersWithOneCapped)
	test.IsEqualBool(t, unlimitedTimeMixed, false)
	test.IsEqualInt64(t, expireAt, 1234567890)
	test.IsEqualBool(t, unlimitedDownloadsMixed, false)
	test.IsEqualInt(t, downloadsRemaining, 7)
}

// TestDeriveBundleSettingsFromMembersNoMembers proves a memberless bundle keeps every field at
// its zero value - already the least accessible state a bundle can be in.
func TestDeriveBundleSettingsFromMembersNoMembers(t *testing.T) {
	passwordHash, expireAt, unlimitedTime, downloadsRemaining, unlimitedDownloads := DeriveBundleSettingsFromMembers(nil)
	test.IsEqualString(t, passwordHash, "")
	test.IsEqualInt64(t, expireAt, 0)
	test.IsEqualBool(t, unlimitedTime, false)
	test.IsEqualInt(t, downloadsRemaining, 0)
	test.IsEqualBool(t, unlimitedDownloads, false)
}
