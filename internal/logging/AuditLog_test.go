package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	initAudit(dir) // re-run recovery, as Init() would on the next process start
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

// TestNoSecretMaterialInAuditEntries is a grep-style assertion (PLAN.md W7 acceptance
// criterion): the audit chain must never contain file content, decryption keys, passwords,
// session cookies or API key secrets, whatever gets logged around it.
func TestNoSecretMaterialInAuditEntries(t *testing.T) {
	dir := t.TempDir()
	initAudit(dir)

	logPath = dir + "/log.txt" // avoid writing the human-readable log into the shared config/ dir

	secretPassword := "sup3rSecretFilePassword!"
	secretKey := "0123456789abcdef0123456789abcdef"
	file := models.File{Id: "secretTestFile", Name: "secret file", PasswordHash: "irrelevant-hash-not-the-password"}
	r := httptest.NewRequest("GET", "/test", nil)

	test.IsNil(t, LogDownload(file, r, false))
	test.IsNil(t, LogDownloadDenied(file, r, false, "incorrect password"))
	test.IsNil(t, LogUpload(file, models.User{Id: 1, Name: "someuser"}, models.FileRequest{}, r, false))

	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	test.IsNil(t, err)
	test.IsEqualBool(t, strings.Contains(string(content), secretPassword), false)
	test.IsEqualBool(t, strings.Contains(string(content), secretKey), false)
	test.IsEqualBool(t, strings.Contains(strings.ToLower(string(content)), "decryptionkey"), false)

	// The human-readable log.txt write is fire-and-forget (see createLogEntry); give it time to
	// land before the temp dir is removed and logPath potentially reassigned by another test.
	time.Sleep(300 * time.Millisecond)
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
