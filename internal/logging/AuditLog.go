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
    first entry ever written), and Hash = SHA-256(PrevHash || canonical JSON of the entry
    with Hash cleared). A later signer only needs to countersign the most recent Hash: that
    transitively covers every entry back to the first one, without touching any of them.
  - The "canonical JSON" is simply encoding/json applied to a fixed struct: Go serialises
    struct fields in declaration order and this package never puts a map or an interface{}
    value into an entry, so the encoding is already deterministic without a bespoke
    canonicaliser.
Nothing here is signed yet (that is a later work item); the chain exists from the first
entry so that when signing is added, all history already collected is covered.
*/

import (
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
}

var auditLogPath = "config/audit.jsonl"
var auditMutex sync.Mutex
var auditNextSeq uint64 = 1
var auditPrevHash = ""

// initAudit sets the path of the audit chain file and recovers Seq/PrevHash from it, so that
// a restart continues the same chain instead of starting a new one.
func initAudit(filePath string) {
	auditLogPath = filePath + "/audit.jsonl"
	recoverAuditChainState()
}

// recoverAuditChainState reads the tail of the audit log (bounded to the last 64KiB, several
// hundred entries at typical sizes) and resumes the chain from the last entry that parses
// correctly. If the very end of the file is an incomplete JSON line - the shape a crash mid
// fsync would leave - it is skipped and reported, but never deleted: the file is append-only
// evidence and this package never truncates or rewrites it.
func recoverAuditChainState() {
	auditNextSeq = 1
	auditPrevHash = ""

	const tailWindow = 64 * 1024
	f, err := os.Open(auditLogPath)
	if err != nil {
		return // no existing chain to resume (missing or unreadable): start a fresh one
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return
	}
	offset := int64(0)
	if info.Size() > tailWindow {
		offset = info.Size() - tailWindow
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		fmt.Println("audit: could not read existing audit log, starting a new chain from seq 1:", err)
		return
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		fmt.Println("audit: could not read existing audit log, starting a new chain from seq 1:", err)
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
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Hash != "" {
			if badTail > 0 {
				fmt.Printf("audit: recovered chain state from entry seq %d after skipping %d unparsable trailing line(s), "+
					"likely a partial write from a crash; the malformed data was left in place for forensic review\n", entry.Seq, badTail)
			}
			auditNextSeq = entry.Seq + 1
			auditPrevHash = entry.Hash
			return
		}
		badTail++
	}
	if badTail > 0 {
		fmt.Println("audit: audit log tail could not be parsed, likely a partial write from a crash; starting a new chain " +
			"from seq 1. The malformed data was left in place for forensic review.")
	}
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

// appendAuditEntry assigns Seq/PrevHash/Hash/Timestamp/Version, appends the entry to the audit
// chain and fsyncs it before returning. It blocks until the write is durable on local storage;
// it never ships anything over the network. Callers on a "serve bytes" path (downloads) or a
// "confirm creation" path (uploads) must treat a non-nil error as a reason to refuse the
// request rather than proceed, so that nothing happens without a durable record of it.
func appendAuditEntry(entry AuditEntry) error {
	auditMutex.Lock()
	defer auditMutex.Unlock()

	entry.Version = auditFormatVersion
	entry.Timestamp = time.Now().Unix()
	entry.Seq = auditNextSeq
	entry.PrevHash = auditPrevHash
	entry.Hash = ""

	preImage, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: could not canonicalise entry: %w", err)
	}
	sum := sha256.Sum256(append([]byte(entry.PrevHash), preImage...))
	entry.Hash = hex.EncodeToString(sum[:])

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: could not serialise entry: %w", err)
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
	auditPrevHash = entry.Hash
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
