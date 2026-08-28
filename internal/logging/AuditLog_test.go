package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

func TestAuditChainSequentialAndHashLinked(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDownload, Action: "download", Outcome: OutcomeSuccess, FileId: "f1"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryUpload, Action: "upload", Outcome: OutcomeSuccess, FileId: "f2"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDenied, Action: "download", Outcome: OutcomeDenied, FileId: "f3"}))

	entries := readAuditEntries(t, dir)
	test.IsEqualInt(t, len(entries), 3)

	test.IsEqual(t, entries[0].Seq, uint64(1))
	test.IsEqual(t, entries[1].Seq, uint64(2))
	test.IsEqual(t, entries[2].Seq, uint64(3))
	test.IsEqualString(t, entries[0].PrevHash, "")
	test.IsEqualString(t, entries[1].PrevHash, entries[0].Hash)
	test.IsEqualString(t, entries[2].PrevHash, entries[1].Hash)
	test.IsNotEmpty(t, entries[0].Hash)
	test.IsEqual(t, entries[0].Version, auditFormatVersion)

	// Recompute entries[1]'s hash independently (not just relying on internal consistency)
	// to verify the chain actually reflects PrevHash || canonical entry, as documented.
	recomputed := entries[1]
	recomputed.Hash = ""
	preImage, err := json.Marshal(recomputed)
	test.IsNil(t, err)
	sum := sha256.Sum256(append([]byte(recomputed.PrevHash), preImage...))
	test.IsEqualString(t, hex.EncodeToString(sum[:]), entries[1].Hash)
}

func TestAuditChainResumesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess}))

	// Simulate a process restart: re-run the same recovery Init() performs on startup.
	initAudit(dir)
	test.IsEqual(t, auditNextSeq, uint64(3))

	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess}))
	entries := readAuditEntries(t, dir)
	test.IsEqualInt(t, len(entries), 3)
	test.IsEqual(t, entries[2].Seq, uint64(3))
	test.IsEqualString(t, entries[2].PrevHash, entries[1].Hash)
}

func TestAuditChainRecoversFromTornWrite(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess}))

	// Simulate a crash mid-fsync: append a truncated, non-JSON line as the file's tail, the
	// shape a partial write would leave.
	f, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	test.IsNil(t, err)
	_, err = f.WriteString(`{"version":1,"seq":3,"prevHash":"ab`)
	test.IsNil(t, err)
	test.IsNil(t, f.Close())

	initAudit(dir)                           // re-run recovery, as Init() would on the next process start
	test.IsEqual(t, auditNextSeq, uint64(3)) // resumed from the last good entry, not from the torn one

	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess}))

	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	test.IsNil(t, err)
	// The malformed line is never deleted or rewritten - it must still be present, in addition
	// to the two good entries and the newly appended one.
	test.IsEqualBool(t, strings.Contains(string(content), `"seq":3,"prevHash":"ab`), true)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	test.IsEqualInt(t, len(lines), 4)
}

func TestAuditChainMissingFileStartsFresh(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir) // audit.jsonl does not exist yet
	test.IsEqual(t, auditNextSeq, uint64(1))
	test.IsEqualString(t, auditPrevHash, "")
}

// TestAuditChainRejectsTamperedTail verifies that recovery does not just check that the last
// line is syntactically valid JSON with a non-empty Hash field (which a tampered line can
// still be) - it recomputes the hash from the stored bytes and rejects the entry if it does not
// match, falling back to the last entry that does verify.
func TestAuditChainRejectsTamperedTail(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess, FileId: "untouched"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess, FileId: "willBeTampered"}))

	// Tamper with the second entry's content without recomputing its hash - the shape of an
	// on-disk edit, as opposed to a crash-torn write (covered by TestAuditChainRecoversFromTornWrite).
	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	test.IsNil(t, err)
	tampered := strings.Replace(string(content), `"fileId":"willBeTampered"`, `"fileId":"tamperedByAttacker"`, 1)
	test.IsNotEqualString(t, tampered, string(content))
	test.IsNil(t, os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(tampered), 0600))

	initAudit(dir)                           // re-run recovery, as Init() would on the next process start
	test.IsEqual(t, auditNextSeq, uint64(2)) // resumed from entry 1, not the tampered entry 2
	test.IsEqualBool(t, auditChainUnusable, false)

	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess}))
	entries := readAuditEntries(t, dir)
	test.IsEqualInt(t, len(entries), 3) // the two original plus the newly appended one
	test.IsEqual(t, entries[2].Seq, uint64(2))
}

// TestAuditChainUnusableWhenFullyCorrupted verifies the "fail loudly" behaviour for the case
// where nothing in an existing, non-empty audit log can be parsed and verified: rather than
// silently restarting the sequence at 1 (which could collide with unknown sequence numbers
// already on disk), every write must be refused until a human resolves it.
func TestAuditChainUnusableWhenFullyCorrupted(t *testing.T) {
	dir := t.TempDir()
	test.IsNil(t, os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte("not json at all\nneither is this\n"), 0600))

	initAudit(dir)
	test.IsEqualBool(t, auditChainUnusable, true)

	err := appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "file.edited", Outcome: OutcomeSuccess})
	test.IsNotNil(t, err)

	// The unreadable file must not have been touched.
	content, readErr := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	test.IsNil(t, readErr)
	test.IsEqualString(t, string(content), "not json at all\nneither is this\n")
}

// TestNoSecretMaterialInAuditEntries is a grep-style assertion (PLAN.md W7 acceptance
// criterion): the audit chain must never contain file content, decryption keys, passwords,
// session cookies or API key secrets. Real secret-shaped values are fed through every object
// the logging path touches (file password hash, encryption key/nonce, API key secret) so that
// this actually exercises the redaction rather than asserting the absence of strings that were
// never logged in the first place.
func TestNoSecretMaterialInAuditEntries(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	logPath = dir + "/log.txt" // avoid writing the human-readable log into the shared config/ dir

	secretPasswordHash := "sup3rSecretFilePasswordHash-do-not-leak-me"
	secretDecryptionKey := []byte("THIS-IS-A-32-BYTE-SECRET-AES-KEY")
	secretNonce := []byte("secret-nonce")
	file := models.File{
		Id:           "secretTestFile",
		Name:         "secret file",
		PasswordHash: secretPasswordHash,
		Encryption: models.EncryptionInfo{
			IsEncrypted:   true,
			DecryptionKey: secretDecryptionKey,
			Nonce:         secretNonce,
		},
	}
	r := httptest.NewRequest("GET", "/test", nil)

	test.IsNil(t, LogDownload(file, r, false))
	test.IsNil(t, LogDownloadDenied(file, r, false, "incorrect password"))
	test.IsNil(t, LogUpload(file, models.User{Id: 1, Name: "someuser"}, models.FileRequest{}, r, false))
	LogEdit(file, models.User{Id: 1, Name: "someuser"})

	secretApiKeyId := "gk_liveSecretBearerTokenDoNotLeak0123456789"
	apiKey := models.ApiKey{Id: secretApiKeyId, PublicId: "publicKeyId1234", FriendlyName: "test key", UserId: 1}
	LogApiKeyCreated(apiKey, models.User{Id: 1, Name: "someuser"})
	LogApiKeyDeleted(apiKey, models.User{Id: 1, Name: "someuser"})
	LogApiKeyPermissionChanged(apiKey, models.User{Id: 1, Name: "someuser"}, "1", true)

	// Give the synchronous chain a moment to flush the async (non-guarded) events above.
	time.Sleep(300 * time.Millisecond)

	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	test.IsNil(t, err)
	test.IsEqualBool(t, strings.Contains(string(content), secretPasswordHash), false)
	test.IsEqualBool(t, strings.Contains(string(content), string(secretDecryptionKey)), false)
	test.IsEqualBool(t, strings.Contains(string(content), string(secretNonce)), false)
	test.IsEqualBool(t, strings.Contains(string(content), secretApiKeyId), false)
	test.IsEqualBool(t, strings.Contains(strings.ToLower(string(content)), "decryptionkey"), false)

	// Positive control: the redacted API key ID must still appear, proving the API key events
	// above actually produced entries rather than this test passing vacuously.
	test.IsEqualBool(t, strings.Contains(string(content), apiKey.GetRedactedId()), true)
	test.IsEqualBool(t, strings.Contains(string(content), "secretTestFile"), true)

	// The human-readable log.txt write is fire-and-forget (see createLogEntry); give it time to
	// land before the temp dir is removed and logPath potentially reassigned by another test.
	time.Sleep(300 * time.Millisecond)
}

// TestAuditChainVerificationSuccess verifies that GetAuditEntriesSince marks entries
// as verified when their hash chain is intact.
func TestAuditChainVerificationSuccess(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDownload, Action: "download", Outcome: OutcomeSuccess, FileId: "f1"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryUpload, Action: "upload", Outcome: OutcomeSuccess, FileId: "f2"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDenied, Action: "download", Outcome: OutcomeDenied, FileId: "f3"}))

	entries, _ := GetAuditEntriesSince(0, 100)
	test.IsEqualInt(t, len(entries), 3)

	// All entries should be verified
	for i, entry := range entries {
		if entry.Verified == nil {
			t.Errorf("Entry %d should have Verified set, got nil", i)
		} else {
			test.IsEqualBool(t, *entry.Verified, true)
		}
	}
}

// TestAuditChainVerificationTampering verifies that tampering with a middle entry
// marks it and all successors as unverified.
func TestAuditChainVerificationTampering(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDownload, Action: "download", Outcome: OutcomeSuccess, FileId: "f1"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryUpload, Action: "upload", Outcome: OutcomeSuccess, FileId: "f2"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDenied, Action: "download", Outcome: OutcomeDenied, FileId: "f3"}))

	// Tamper with the second entry's content without recomputing its hash
	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	test.IsNil(t, err)
	tampered := strings.Replace(string(content), `"fileId":"f2"`, `"fileId":"f2tampered"`, 1)
	test.IsNotEqualString(t, tampered, string(content))
	test.IsNil(t, os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(tampered), 0600))

	entries, _ := GetAuditEntriesSince(0, 100)
	test.IsEqualInt(t, len(entries), 3)

	// First entry should be verified
	test.IsNotNil(t, entries[0].Verified)
	test.IsEqualBool(t, *entries[0].Verified, true)

	// Second entry should be unverified (content tampered)
	test.IsNotNil(t, entries[1].Verified)
	test.IsEqualBool(t, *entries[1].Verified, false)

	// Third entry should be unverified (predecessor failed)
	test.IsNotNil(t, entries[2].Verified)
	test.IsEqualBool(t, *entries[2].Verified, false)
}

// TestAuditChainVerificationDeletion verifies that deleting a line from the middle
// breaks the chain for the next entry.
func TestAuditChainVerificationDeletion(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDownload, Action: "download", Outcome: OutcomeSuccess, FileId: "f1"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryUpload, Action: "upload", Outcome: OutcomeSuccess, FileId: "f2"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDenied, Action: "download", Outcome: OutcomeDenied, FileId: "f3"}))

	// Delete the second line
	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	test.IsNil(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	test.IsEqualInt(t, len(lines), 3)

	// Reconstruct file with only first and third entry
	test.IsNil(t, os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(lines[0]+"\n"+lines[2]+"\n"), 0600))

	entries, _ := GetAuditEntriesSince(0, 100)
	test.IsEqualInt(t, len(entries), 2)

	// First entry should be verified
	test.IsNotNil(t, entries[0].Verified)
	test.IsEqualBool(t, *entries[0].Verified, true)

	// Third entry should be unverified (its prevHash won't match the new predecessor)
	test.IsNotNil(t, entries[1].Verified)
	test.IsEqualBool(t, *entries[1].Verified, false)
}

// TestAuditChainLegacyLinesOmitVerified verifies that legacy entries without a hash
// field have Verified omitted from JSON (serialized as nil).
func TestAuditChainLegacyLinesOmitVerified(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	// Manually write a legacy entry without a hash field
	// We write raw JSON without the hash field to simulate a legacy entry from before hashing was added
	legacyJson := `{"version":1,"seq":1,"prevHash":"","timestamp":` +
		fmt.Sprintf("%d", time.Now().Unix()) +
		`,"category":"download","action":"download","outcome":"success","ip":"","fileId":"f1","requestId":"","actor":{"userId":0,"email":"","oidcSubject":"","anonymous":true}}`

	// Write it to the file (simulate a legacy entry from before hashing was added)
	test.IsNil(t, os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(legacyJson+"\n"), 0600))

	// Now recover state from the legacy entry
	initAudit(dir)

	entries, _ := GetAuditEntriesSince(0, 100)
	test.IsEqualInt(t, len(entries), 1)

	// Legacy entry should have Verified as nil
	if entries[0].Verified != nil {
		t.Errorf("Expected Verified to be nil for legacy entry, got: %v", *entries[0].Verified)
	}

	// Verify JSON serialization omits the verified field
	jsonBytes, err := json.Marshal(entries[0])
	test.IsNil(t, err)
	jsonStr := string(jsonBytes)
	test.IsEqualBool(t, strings.Contains(jsonStr, "verified"), false)
}

// TestAuditChainVerificationWithCursor verifies that GetAuditEntriesSince maintains
// verification from file start regardless of the fromSeq cursor.
func TestAuditChainVerificationWithCursor(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDownload, Action: "download", Outcome: OutcomeSuccess, FileId: "f1"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryUpload, Action: "upload", Outcome: OutcomeSuccess, FileId: "f2"}))
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryDenied, Action: "download", Outcome: OutcomeDenied, FileId: "f3"}))

	// Request entries starting from seq 2 (skip first entry)
	entries, _ := GetAuditEntriesSince(1, 100)
	test.IsEqualInt(t, len(entries), 2) // Should get entries 2 and 3

	// Both should still be verified because verification ran from file start
	test.IsNotNil(t, entries[0].Verified)
	test.IsEqualBool(t, *entries[0].Verified, true)
	test.IsNotNil(t, entries[1].Verified)
	test.IsEqualBool(t, *entries[1].Verified, true)
}

// TestAuditChainBatchedFolderDeleteSingleWrite verifies MAJOR-2: a folder delete with several
// member files produces one correctly hash-chained batch (one entry per member plus one for the
// folder itself) via a single call to appendAuditEntries, rather than the N+1 separate
// appendAuditEntry calls (each its own mutex acquisition, file open and fsync) that a folder
// delete with thousands of members used to make.
func TestAuditChainBatchedFolderDeleteSingleWrite(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	entries := []AuditEntry{
		{Category: categoryEdit, Action: "file.deleted", Outcome: OutcomeSuccess, FileId: "batchMember1"},
		{Category: categoryEdit, Action: "file.deleted", Outcome: OutcomeSuccess, FileId: "batchMember2"},
		{Category: categoryEdit, Action: "file.deleted", Outcome: OutcomeSuccess, FileId: "batchMember3"},
		{Category: categoryEdit, Action: "folder.deleted", Outcome: OutcomeSuccess, BundleId: "batchBundleId"},
	}
	test.IsNil(t, appendAuditEntries(entries))
	test.IsEqual(t, auditNextSeq, uint64(5))

	stored := readAuditEntries(t, dir)
	test.IsEqualInt(t, len(stored), 4)
	test.IsEqualString(t, stored[0].PrevHash, "")
	for i := 1; i < len(stored); i++ {
		test.IsEqualString(t, stored[i].PrevHash, stored[i-1].Hash)
	}
	test.IsEqualString(t, stored[3].Action, "folder.deleted")
	test.IsEqualString(t, stored[3].BundleId, "batchBundleId")
}

// TestAuditChainBatchedWriteAllOrNothingOnFailure verifies MAJOR-2/MINOR-2: appendAuditEntries
// (used by LogFolderDeleteBatch for a folder delete) writes every entry in a batch as a single
// all-or-nothing unit. It uses a small RLIMIT_FSIZE so the combined write fails partway through
// writing the batch, rather than failing outright on the very first byte - a fault that fails
// immediately would pass even against the pre-fix per-member appendAuditEntry loop, since that
// loop's very first call would also fail immediately with no partial writes. This fault instead
// lets a small first write succeed and only the larger combined write overflow the limit, which
// is exactly the shape of failure that let the old per-member loop durably write the first few
// members' "deleted" entries before erroring out on a later one - entries the caller then treats
// as fatal and aborts the delete on, leaving those already-written entries false. The batched
// write must leave the chain exactly as it was before the call in every case.
func TestAuditChainBatchedWriteAllOrNothingOnFailure(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	// Prime the chain with one small entry so the audit file already has durable content and a
	// non-empty PrevHash to preserve.
	test.IsNil(t, appendAuditEntry(AuditEntry{Category: categoryEdit, Action: "priming", Outcome: OutcomeSuccess}))
	seqBefore := auditNextSeq
	prevHashBefore := auditPrevHash

	// The margin allows exactly one further ~300-byte entry to fit (this is the fault that
	// differentiates the old per-member loop from the new batched write: the loop's first
	// member write fits and durably lands before the second one overflows the limit, while the
	// batched write asks for all three entries - well over 600 bytes - in a single write call).
	restoreLimit := limitAuditFileSize(t, dir, 350)
	defer restoreLimit()

	entries := []AuditEntry{
		{Category: categoryEdit, Action: "file.deleted", Outcome: OutcomeSuccess, FileId: "batchFailMember1"},
		{Category: categoryEdit, Action: "file.deleted", Outcome: OutcomeSuccess, FileId: "batchFailMember2"},
		{Category: categoryEdit, Action: "folder.deleted", Outcome: OutcomeSuccess, BundleId: "batchFailBundle"},
	}
	err := appendAuditEntries(entries)
	test.IsNotNil(t, err)

	test.IsEqual(t, auditNextSeq, seqBefore)
	test.IsEqualString(t, auditPrevHash, prevHashBefore)

	// A failed write can still leave a torn, incomplete line physically in the file (the OS may
	// write some bytes before hitting the size limit, even though Sync is never reached) - use
	// GetAuditEntriesSince rather than a raw line-by-line read, since it is the production reader
	// and already tolerates exactly this (see its "Parse error, skip this line" handling), the
	// same way a real crash-torn tail is tolerated on the next startup.
	stored, _ := GetAuditEntriesSince(0, 100)
	for _, e := range stored {
		isFalseMemberRecord := e.Action == "file.deleted" && (e.FileId == "batchFailMember1" || e.FileId == "batchFailMember2")
		isFalseFolderRecord := e.Action == "folder.deleted" && e.BundleId == "batchFailBundle"
		test.IsEqualBool(t, isFalseMemberRecord || isFalseFolderRecord, false)
	}
}

func readAuditEntries(t *testing.T, dir string) []AuditEntry {
	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	test.IsNil(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	entries := make([]AuditEntry, 0, len(lines))
	for _, line := range lines {
		var e AuditEntry
		err = json.Unmarshal([]byte(line), &e)
		test.IsNil(t, err)
		entries = append(entries, e)
	}
	return entries
}
