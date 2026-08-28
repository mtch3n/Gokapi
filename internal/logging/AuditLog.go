package logging

/**
Structured, chained audit events.

Every audit-relevant action in Gokapi (uploads, downloads, denials, deletions, expiry,
share/file-request lifecycle, login/logout, user and API key management, encryption
configuration changes) is additionally recorded here as one canonical JSON line, on top
of the existing human-readable log.txt.

The record format is designed so that hash-chaining and signing (a later work item) can be
switched on without migrating or re-canonicalising anything written before that point:
  - Version is a schema version. A future format change adds a new value here rather than
    reinterpreting old entries.
  - Seq is a strictly monotonic sequence number, gap-free across everything that was
    successfully written (a write that fails does not consume a sequence number).
  - PrevHash links every entry to the hash of the one before it (the empty string for the
    first entry ever written).
  - Hash field placement and the verification rule (this is what a verifier, e.g. W16, should
    implement): Hash is declared last in AuditEntry and has no `omitempty`, so it is always
    the final "hash":"<64 hex chars>"} in the stored line. Both writing and verifying work
    directly on those bytes, never on a second call to encoding/json:
      - To write: marshal the entry once with Hash == "" (giving a line ending in
        "hash":""}), compute SHA-256(PrevHash || thatLine), and splice the resulting hex
        string into the empty hash value directly in the byte slice. See
        finalizeEntryLine().
      - To verify a stored line: take its exact bytes, replace the value of the trailing
        "hash":"..." field with "" (undoing exactly the splice above), compute
        SHA-256(PrevHash || clearedLine), and compare to the hash that was in the line. See
        recomputeEntryHash(), used both by startup recovery and by any future verifier.
    Because both directions operate on raw stored bytes rather than re-serialising the parsed
    Go struct, a verifier never has to reproduce encoding/json's output on any Go version,
    past or future - it only has to do the string splice above.
A later signer only needs to countersign the most recent Hash: that transitively covers every
entry back to the first one, without touching any of them. Nothing here is signed yet (that is
a later work item); the chain exists from the first entry so that when signing is added, all
history already collected is covered.
*/

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/forceu/gokapi/internal/models"
)

// auditFormatVersion is the schema version written into every audit entry.
const auditFormatVersion = 1

// AuditOutcome is the result of an audited action.
type AuditOutcome string

const (
	// OutcomeSuccess indicates the action completed as requested.
	OutcomeSuccess AuditOutcome = "success"
	// OutcomeFailure indicates the action failed for a technical reason (e.g. storage error).
	OutcomeFailure AuditOutcome = "failure"
	// OutcomeDenied indicates the action was refused by policy (e.g. wrong password, exhausted link).
	OutcomeDenied AuditOutcome = "denied"
)

// AuditActor identifies who performed an audited action.
//
// Email holds the authenticated user's Name field: for OAuth logins Gokapi already uses the
// verified email address as the username (see authentication.getOrCreateUser), for internal
// auth it is the account username. OidcSubject is only ever populated on the login event
// itself, as it is the only point in the request lifecycle where Gokapi still has it -
// sessions created afterwards do not carry the OIDC subject, so later actions by the same
// user cannot be tied back to it. Anonymous is true for public, unauthenticated access such
// as a share link download, where by design no identity exists to record.
type AuditActor struct {
	UserId      int    `json:"userId,omitempty"`
	Email       string `json:"email,omitempty"`
	OidcSubject string `json:"oidcSubject,omitempty"`
	Anonymous   bool   `json:"anonymous,omitempty"`
}

// AuditFileConfig captures the configuration of a file/share at the time of the event, so a
// later reviewer does not need to (and, for a deleted file, cannot) look it up again.
// PasswordProtected doubles as "whether auth was required" for a share: Gokapi has no other
// access control on a public download/upload link.
type AuditFileConfig struct {
	OneTime           bool  `json:"oneTime,omitempty"`
	ExpiresAt         int64 `json:"expiresAt,omitempty"`
	PasswordProtected bool  `json:"passwordProtected,omitempty"`
}

// AuditEntry is one immutable record in the audit chain. See the package doc comment for the
// chaining design. Never populate a field with file content, a decryption key, a password or
// any other secret material - this log is intended to be retained and reviewed far more
// broadly than that would be safe for.
type AuditEntry struct {
	Version    int              `json:"version"`
	Seq        uint64           `json:"seq"`
	PrevHash   string           `json:"prevHash"`
	Timestamp  int64            `json:"timestamp"`
	Category   string           `json:"category"`
	Action     string           `json:"action"`
	Outcome    AuditOutcome     `json:"outcome"`
	Ip         string           `json:"ip,omitempty"`
	FileId     string           `json:"fileId,omitempty"`
	RequestId  string           `json:"requestId,omitempty"`
	Actor      AuditActor       `json:"actor"`
	FileConfig *AuditFileConfig `json:"fileConfig,omitempty"`
	// Detail is a short free-form description for event-specific context that does not
	// warrant its own field (e.g. which permission changed, old/new encryption level, the
	// name of an affected user or API key). Never file content or secret material.
	Detail string `json:"detail,omitempty"`
	// Error is populated on Outcome Failure or Denied with a human-readable reason.
	Error string `json:"error,omitempty"`
	Hash  string `json:"hash"`
	// Verified is set to true if the entry's hash chain is intact; nil for legacy entries
	// without a hash field, so they serialize with the field omitted via omitempty.
	Verified *bool `json:"verified,omitempty"`
}

var auditLogPath = "config/audit.jsonl"
var auditMutex sync.Mutex
var auditNextSeq uint64 = 1
var auditPrevHash = ""

// auditChainUnusable is set when recovery finds an existing, non-empty audit log in which not
// a single entry parses and self-verifies. That is not the ordinary torn-tail case (a crash mid
// fsync corrupts at most the last line); it means the file's sequence/hash state cannot be
// trusted at all. Silently starting a fresh chain at seq 1 in that situation would produce
// duplicate sequence numbers on disk that no future verifier could reconcile, so instead every
// write is refused (see appendAuditEntry) until the file is manually moved aside or repaired.
var auditChainUnusable = false

// initAudit sets the path of the audit chain file and recovers Seq/PrevHash from it, so that
// a restart continues the same chain instead of starting a new one.
func initAudit(filePath string) {
	auditLogPath = filePath + "/audit.jsonl"
	recoverAuditChainState()
}

// recoverAuditChainState reads the audit log and resumes the chain from the last entry that
// both parses and self-verifies (its own Hash matches SHA-256(PrevHash || the line with the
// hash cleared), recomputed from the exact stored bytes - see recomputeEntryHash). If the very
// end of the file is an incomplete or tampered line, it is skipped and reported, but never
// deleted: the file is append-only evidence and this package never truncates or rewrites it.
// If nothing in the whole file verifies, the chain is marked unusable rather than silently
// restarting at seq 1 (see auditChainUnusable).
func recoverAuditChainState() {
	auditNextSeq = 1
	auditPrevHash = ""
	auditChainUnusable = false

	f, err := os.Open(auditLogPath)
	if err != nil {
		return // no existing chain to resume (missing or unreadable): start a fresh one
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		fmt.Println("audit: could not stat existing audit log, refusing to append to it until this is resolved:", err)
		auditChainUnusable = true
		return
	}
	if info.Size() == 0 {
		return
	}

	// The whole file is read rather than only its tail: a bounded read would let an entry that
	// still verifies further back in the file go undiscovered, forcing an unnecessary restart
	// at seq 1. Audit logs for a self-hosted file-sharing instance are not expected to reach a
	// size where a one-time read at startup is a problem; if that changes, retention (a
	// deferred, separate work item) is the right fix, not skipping verification here.
	buf, err := io.ReadAll(f)
	if err != nil {
		fmt.Println("audit: could not read existing audit log, refusing to append to it until this is resolved:", err)
		auditChainUnusable = true
		return
	}

	// If the file does not end in a newline, the last write was interrupted mid-line (e.g. a
	// crash mid-fsync). The partial bytes are left in place as forensic evidence, but a newline
	// is appended so that the next entry written starts on its own line instead of being
	// concatenated onto the torn one, which would otherwise corrupt every entry written after it.
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		ensureTrailingNewline()
	}

	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	badTail := 0
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			// Accept entries that either:
			// 1. Have a valid hash (entry.Hash != "" and it matches recomputed)
			// 2. Are legacy entries without a hash field (entry.Hash == "")
			if entry.Hash == "" {
				// Legacy entry without hash field; accept it and resume from here
				if badTail > 0 {
					fmt.Printf("audit: recovered chain state from legacy entry seq %d (no hash field) after skipping %d "+
						"unparsable or unverifiable trailing line(s), likely a partial write from a crash or legacy data; "+
						"the malformed data was left in place for forensic review\n", entry.Seq, badTail)
				}
				auditNextSeq = entry.Seq + 1
				auditPrevHash = "" // Legacy entries have no hash to link from
				return
			}
			// Entry has a hash field; verify it
			if recomputed, ok := recomputeEntryHash(line, entry.PrevHash); ok && recomputed == entry.Hash {
				if badTail > 0 {
					fmt.Printf("audit: recovered chain state from entry seq %d after skipping %d unparsable or "+
						"unverifiable trailing line(s), likely a partial write from a crash; the malformed data was "+
						"left in place for forensic review\n", entry.Seq, badTail)
				}
				auditNextSeq = entry.Seq + 1
				auditPrevHash = entry.Hash
				return
			}
		}
		badTail++
	}
	// Nothing in the file parsed and self-verified. Unlike the small torn-tail case this covers
	// the whole file, which is unexplained corruption rather than an interrupted last write:
	// refuse to append until a human resolves it (see auditChainUnusable), rather than silently
	// starting a fresh chain that could collide with whatever sequence numbers are already
	// sitting unverified on disk.
	fmt.Println("audit: audit log exists but no entry in it could be parsed and verified; refusing to append to it until " +
		"this is resolved manually (e.g. by moving the file aside so a fresh chain can start). Not deleting or " +
		"modifying the existing file.")
	auditChainUnusable = true
}

// ensureTrailingNewline appends a single newline byte to the audit log if a prior write was
// left without one, so that a torn tail from a crash never gets prepended onto the next entry.
// It never touches or removes any existing byte.
func ensureTrailingNewline() {
	f, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err = f.WriteString("\n"); err != nil {
		return
	}
	_ = f.Sync()
}

// hashFieldSuffix is the exact tail every stored line has while its hash value is still empty:
// Hash is declared last in AuditEntry with no `omitempty`, so a marshaled entry with Hash == ""
// always ends in exactly this. finalizeEntryLine and recomputeEntryHash both rely on it.
const hashFieldSuffix = `"hash":""}`

// finalizeEntryLine takes preImage - json.Marshal(entry) with entry.Hash == "" - and prevHash,
// computes hash = SHA-256(prevHash || preImage), and returns the final line with that hash
// spliced directly into the trailing hash value: no second call to encoding/json is made, so
// the stored bytes are guaranteed to be exactly preImage with only the hash value filled in.
// See the package doc comment for why this, rather than re-marshaling, is the format's
// verification rule.
func finalizeEntryLine(preImage []byte, prevHash string) (line []byte, hashHex string, ok bool) {
	s := string(preImage)
	if !strings.HasSuffix(s, hashFieldSuffix) {
		return nil, "", false
	}
	sum := sha256.Sum256(append([]byte(prevHash), preImage...))
	hashHex = hex.EncodeToString(sum[:])
	// Drop the trailing `"}` (the empty value's closing quote and the entry's closing brace),
	// leaving the line ending right after the value's opening quote, then fill in the hash.
	return []byte(s[:len(s)-2] + hashHex + `"}`), hashHex, true
}

// recomputeEntryHash is the inverse of finalizeEntryLine: given the exact bytes of a stored
// line and the prevHash it claims, it strips the line's own hash value back out (recovering the
// same preImage finalizeEntryLine hashed), recomputes SHA-256(prevHash || preImage) and returns
// it for the caller to compare against the hash actually stored in the line. Used by startup
// recovery, and is the rule any later external verifier should implement.
func recomputeEntryHash(line string, prevHash string) (hashHex string, ok bool) {
	const marker = `"hash":"`
	idx := strings.LastIndex(line, marker)
	if idx == -1 || !strings.HasSuffix(line, `"}`) {
		return "", false
	}
	valueStart := idx + len(marker)
	if valueStart > len(line)-2 {
		return "", false
	}
	cleared := line[:valueStart] + `"}` // same shape finalizeEntryLine started from
	sum := sha256.Sum256(append([]byte(prevHash), []byte(cleared)...))
	return hex.EncodeToString(sum[:]), true
}

// appendAuditEntry assigns Seq/PrevHash/Hash/Timestamp/Version, appends the entry to the audit
// chain and fsyncs it before returning. It blocks until the write is durable on local storage;
// it never ships anything over the network. Callers on a "serve bytes" path (downloads) or a
// "confirm creation" path (uploads) must treat a non-nil error as a reason to refuse the
// request rather than proceed, so that nothing happens without a durable record of it.
func appendAuditEntry(entry AuditEntry) error {
	auditMutex.Lock()
	defer auditMutex.Unlock()

	if auditChainUnusable {
		return fmt.Errorf("audit: chain state could not be recovered from an existing, unverifiable audit log at %s; "+
			"refusing to append until this is resolved manually", auditLogPath)
	}

	entry.Version = auditFormatVersion
	entry.Timestamp = time.Now().Unix()
	entry.Seq = auditNextSeq
	entry.PrevHash = auditPrevHash
	entry.Hash = ""

	preImage, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: could not canonicalise entry: %w", err)
	}
	line, hashHex, ok := finalizeEntryLine(preImage, entry.PrevHash)
	if !ok {
		return fmt.Errorf("audit: marshaled entry did not have the expected trailing empty hash field")
	}

	file, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("audit: could not open audit log: %w", err)
	}
	defer file.Close()

	if _, err = file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: could not write audit entry: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("audit: could not fsync audit log: %w", err)
	}

	auditNextSeq++
	auditPrevHash = hashHex
	return nil
}

// appendAuditEntryAsync is used for audit-relevant events that are not on a "serve bytes" or
// "confirm creation" path (logins, logouts, edits, deletions, user/API key/config management,
// automatic expiry). These still become part of the same chain - so W15 can checkpoint over
// all of it - but a local write failure here is reported rather than refusing the request,
// mirroring today's fire-and-forget log.txt writes for these categories.
func appendAuditEntryAsync(entry AuditEntry) {
	go func() {
		if err := appendAuditEntry(entry); err != nil {
			fmt.Println("audit: failed to record event (category "+entry.Category+", action "+entry.Action+"):", err)
		}
	}()
}

type actorContextKey int

const requestActorContextKey actorContextKey = 0

// WithActor returns a shallow copy of r with user attached, so that a download served through
// r can be attributed to an authenticated admin/API user instead of being recorded as an
// anonymous share access. storage.ServeFile reads this back via actorFromRequest; it never
// gains a dependency on the webserver/authentication package for this.
func WithActor(r *http.Request, user models.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestActorContextKey, user))
}

// actorFromRequest returns the user attached via WithActor, if any.
func actorFromRequest(r *http.Request) (models.User, bool) {
	if r == nil {
		return models.User{}, false
	}
	user, ok := r.Context().Value(requestActorContextKey).(models.User)
	return user, ok
}

// buildActorFromRequest builds an AuditActor from a request that may or may not have gone
// through WithActor: authenticated when an actor was attached, anonymous otherwise (the
// expected case for public share/hotlink downloads).
func buildActorFromRequest(r *http.Request) AuditActor {
	if user, ok := actorFromRequest(r); ok {
		return AuditActor{UserId: user.Id, Email: user.Name}
	}
	return AuditActor{Anonymous: true}
}

// GetAuditEntriesSince reads the audit log file and returns entries whose Seq > fromSeq,
// oldest-first, capped at limit. If limit <= 0, defaults to 500; hard-capped at 2000.
// Also returns lastSeq = the highest Seq present in the file (0 if file does not exist or is empty).
// Parse errors are skipped (corruption tolerance for a read path); blank lines are ignored.
// Verifies the hash chain from the start of the file regardless of fromSeq cursor: each
// returned entry has Verified set to true if its hash chain is intact and its predecessor
// verified, or false if the hash is invalid or its predecessor failed. Legacy entries without
// a hash field are returned with Verified=nil (omitted from JSON output).
// Does not take the append mutex: opens the file read-only and reads independently.
func GetAuditEntriesSince(fromSeq uint64, limit int) ([]AuditEntry, uint64) {
	// Default and cap limit
	if limit <= 0 {
		limit = 500
	}
	if limit > 2000 {
		limit = 2000
	}

	f, err := os.Open(auditLogPath)
	if err != nil {
		// File does not exist yet, return empty
		return []AuditEntry{}, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Set a large buffer to tolerate long lines
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var entries []AuditEntry
	var maxSeq uint64 = 0
	var runningHash = "" // Track hash as we read, starting from empty (genesis constant)
	var predecessorVerified = true // The genesis state is considered verified

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Parse error, skip this line
			continue
		}

		// Track the highest seq seen
		if entry.Seq > maxSeq {
			maxSeq = entry.Seq
		}

		// Verify the hash if present
		if entry.Hash != "" {
			// Entry has a hash field; verify it
			recomputed, ok := recomputeEntryHash(line, runningHash)
			if ok && recomputed == entry.Hash && predecessorVerified {
				// Hash is valid and predecessor verified
				verified := true
				entry.Verified = &verified
				runningHash = entry.Hash
				predecessorVerified = true
			} else {
				// Hash is invalid or predecessor failed
				verified := false
				entry.Verified = &verified
				// Don't update runningHash; this breaks the chain for subsequent entries
				predecessorVerified = false
			}
		} else {
			// Legacy entry without hash; leave Verified as nil (omitted in JSON)
			entry.Verified = nil
		}

		// Only include entries after fromSeq
		if entry.Seq > fromSeq && len(entries) < limit {
			entries = append(entries, entry)
		}
	}

	return entries, maxSeq
}
