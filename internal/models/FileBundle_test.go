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
