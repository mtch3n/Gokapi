# Security Analysis — gokapi-fork (`feat/sealed-box-inbound`, base 618ecf1)

Scope: read-only static review focused on the new PostgreSQL provider (commit 35eccd1)
plus authentication, access control, file handling, crypto, and information disclosure.
Nothing was executed or modified; the `gokapi-test-pg` container was inspected read-only
(it held no tables at review time).

---

## 1. Executive summary

Do **not** treat this build as safe for CONFIDENTIAL healthcare-adjacent data yet.

The two structural problems that matter most are inherited from upstream and are not fixed
here: (a) "Level 3" end-to-end encryption is **symmetric-only** and **guest/file-request
uploads bypass it entirely, landing in plaintext on disk**, and (b) the `isE2E` flag is
client-asserted, so a client can silently downgrade to plaintext. These directly defeat the
"clients upload confidential files to us" use case — the exact inbound path is the one with
no E2E.

The new Postgres provider itself is competently written: **no SQL injection**, fully
parameterized, and it actually *fixes* two upstream bugs (`rows.Err()` handling and the
`UpdateUserLastOnline` arg mismatch). But moving persistence to a networked/managed Postgres
changes the threat model in ways the code does not account for: every DB call `panic`s on a
transient error (a network blip crashes the server), the full DSN **including the password**
is stored in plaintext config and printed to stdout during migration, nothing enforces TLS on
the connection, and download-limit ("one-time file") enforcement relies on a **process-local
mutex** that does not hold across the multiple instances a shared Postgres is meant to enable.

Bottom line: the Postgres port is mergeable after the credential-logging, panic-on-error, and
TLS-enforcement items are addressed, but the product is **not** suitable for confidential
client data until the E2E-bypass / plaintext-inbound behaviour is redesigned.

---

## 2. Findings table

| # | Sev | Area | Summary | Origin |
|---|-----|------|---------|--------|
| F1 | High | Crypto / access | E2E is symmetric-only; **guest file-request uploads bypass E2E and are stored plaintext on disk** | Inherited |
| F2 | High | Upload integrity | `isE2E` upload flag is client-asserted → silent plaintext downgrade | Inherited |
| F3 | High | Availability | Every Postgres call `helper.Check`→`panic`; a remote-DB blip crashes the whole server | Introduced (context) |
| F4 | High | Confidentiality | No TLS enforcement on the Postgres DSN; bearer secrets + all metadata cross the network / sit in a managed DB in cleartext | Introduced (context) |
| F5 | Medium | Info disclosure | Full Postgres DSN (with password) printed to stdout on migration and echoed in a parse error | Introduced |
| F6 | Medium | Access control | Download-limit / one-time-file enforcement is a process-local mutex + non-floored decrement → cap exceeded across instances | Inherited design, worsened by Postgres |
| F7 | Low | Data integrity | `ON CONFLICT (Id)` upserts panic on a *secondary* unique collision where SQLite `INSERT OR REPLACE` silently clobbered (esp. `SaveHotlink` on `FileId`) | Introduced (drift) |
| F8 | Low | Overflow | `uint64` traffic counter stored in signed `BIGINT`; insert fails above ~8 EiB | Introduced |
| F9 | Info | Hygiene | Migration writes a spurious empty `E2EConfig` row for every user | Inherited |

Re-confirmed known items: F1, F2 above; plus the SQLite `UpdateUserLastOnline` 3-arg/2-placeholder
bug (present in `sqlite/users.go:102`, **correctly fixed** in `postgres/users.go:120-122`).

---

## 3. Detailed findings (most severe first)

### F1 — High — E2E bypass: guest/file-request uploads are stored in plaintext (Inherited)

`internal/storage/FileServing.go:500-514`
```go
func isEncryptionRequested() bool {
	switch configuration.Get().Encryption.Level {
	...
	case encryption.EndToEndEncryption:
		return false
	...
```
At encryption level 5 (E2E) the server performs **no** server-side encryption
(`isEncryptionRequested()==false`, and `Encryption.Init` at `internal/encryption/Encryption.go:60`
does `case EndToEndEncryption: return` so the server holds no key). E2E is expected to happen in
the *client* browser using a symmetric master key kept in `localStorage.e2ekey`. A guest filling a
file request has no such key. Therefore the inbound path — the one the business specifically wants
(clients uploading confidential files to us) — writes the file **unencrypted** to `DataDir/<SHA1>`
(`FileServing.go:73, 111, 778`). At-rest storage of confidential client data is unencrypted for
exactly the flow that is supposed to be most protected.

Exploit/scenario: enable Level 3, create a file request, send it to a client. Client uploads a PHI
document. It is stored in plaintext on the server filesystem and its metadata (name, size, SHA1) in
the DB. Anyone with host or DB/backup access reads it.

Fix: for inbound confidential data, do not rely on browser-side symmetric E2E. Either (a) force
server-side full encryption (Level 3/4) for file-request uploads regardless of the E2E toggle, or
(b) implement genuine asymmetric sealed-box encryption to the recipient's public key (the branch
name `sealed-box-inbound` suggests this is the intent — it is not implemented; `grep -rE
'ecdh|x25519|nacl/box'` finds nothing).

### F2 — High — Client-asserted `isE2E` flag enables silent downgrade (Inherited)

`internal/webserver/fileupload/FileUpload.go:178-186`
```go
if values.Get("isE2E") == "true" {
	isEnd2End = true
	realSizeStr := values.Get("realSize")
	...
```
The server trusts a client-supplied form value to decide whether a file is E2E-encrypted, and
`realSize` (used for accounting/UX) is also attacker-controlled. Combined with F1 (server never
encrypts at Level 5), a malicious or buggy client can post `isE2E=false` and upload plaintext, or
`isE2E=true` over plaintext content to mislead the operator's UI into believing content is
protected. The server cannot distinguish.

Fix: the encryption decision must be server-authoritative, derived from server config, not a form
field. If E2E metadata must be recorded, verify it (e.g. presence of a wrapped key blob) rather
than trusting a boolean.

### F3 — High — Panic-on-DB-error turns a remote Postgres into a crash oracle (Introduced, context)

Every method in the Postgres provider ends in `helper.Check(err)`, which is:
`internal/helper/OS.go:64-68`
```go
func Check(err error) { if err != nil { panic(err) } }
```
Examples: `postgres/metadata.go:80,85,91` (`GetAllMetadata`), `postgres/apikeys.go:51,57`
(`GetAllApiKeys`, on the hot auth path via `GetApiKey`), `postgres/sessions.go` (session lookups),
etc. With SQLite (a local file) I/O errors are rare, so the panic pattern is tolerable. With a
**remote/managed** Postgres — the entire reason this provider exists — a connection reset, a
failover, a `statement_timeout`, or the pool being exhausted raises an error on a normal request
and panics the process. There is no retry, no context timeout, and no graceful 5xx. A client that
can induce load or catch a maintenance window can repeatedly crash the server (availability/DoS),
and any confidential-data service needs availability guarantees.

Refutation attempt: could a recover middleware catch it? Go's `net/http` recovers per-goroutine
panics for the *request*, but shared state and the connection pool can be left inconsistent, and
background goroutines (`go database.UpdateUserLastOnline(...)` at `SessionManager.go:54`) panic
with **no** recovery → whole-process crash. Confirmed reachable.

Fix: the provider should return errors up the stack (or at minimum use `CheckIgnoreTimeout` and add
`context.WithTimeout` + bounded retries for transient classes). Do not `panic` on network I/O in a
networked provider.

### F4 — High — No TLS enforcement; bearer secrets and all metadata exposed to the DB tier (Introduced, context)

Setup only validates the URL *scheme*, never the transport:
`internal/configuration/setup/Setup.go:367-378`
```go
if !strings.HasPrefix(dbUrl, "postgres://") && !strings.HasPrefix(dbUrl, "postgresql://") {
	return errors.New("postgres connection string must start with postgres:// or postgresql://")
}
result.DatabaseUrl = dbUrl
```
`sslmode` is whatever the operator typed; `sslmode=disable` is accepted silently (the test DSN in
`postgres/Postgres_test.go:15` uses exactly that). What crosses that connection, and what then lives
inside a managed/shared Postgres, includes bearer credentials and sensitive metadata:

- **API key IDs** are the bearer secret and are stored as the plaintext primary key
  (`ApiKeys.Id`, `postgres/Postgres.go:122`); auth is a direct `WHERE Id = $1` lookup
  (`postgres/apikeys.go:67`).
- **Session tokens** are the cookie value stored plaintext as `Sessions.Id`
  (`postgres/sessions.go:22`, written from `sessionmanager` `session_token` cookie).
- File names, SHA1s, `PasswordHash`, and the gob-encoded `E2EConfig`.

On the local SQLite file this is a single-trust-boundary concern. On a managed Postgres it exposes
these to the DB provider's staff, backups, replicas, and any other app on that instance. A read-only
DB compromise yields live admin session tokens and API keys → full impersonation.

Fix: require `sslmode=require` (or stronger) at setup; reject `disable`/`prefer`. Consider storing
only hashes of session tokens and API key IDs (lookup by hash) so a DB read does not yield usable
bearer credentials. This last point is inherited but becomes materially more important with a
networked DB.

### F5 — Medium — DSN with password leaked to stdout/logs (Introduced)

`internal/configuration/database/migration/Migration.go:25`
```go
fmt.Printf("Migrating %s database %s to %s database %s\n",
	getType(oldDb.Type), oldDb.HostUrl, getType(newDb.Type), newDb.HostUrl)
```
For Postgres, `HostUrl` is the **entire DSN** (`Database.go:56-58` sets `result.HostUrl = dbUrl`),
i.e. `postgres://user:password@host/db`. Redis/SQLite `HostUrl` carries no password, so this print
was previously benign; for Postgres it writes the DB password to the console and any capturing log.
Additionally the unsupported-scheme error echoes the full URL:
`internal/configuration/database/Database.go:59` → `fmt.Errorf("unsupported database type: %s\n",
dbUrl)`, so a typo'd scheme (`postgre://user:pass@…`) surfaces the password in an error string that
is printed at `Migration.go:15/21`. Setup itself (`setup.tmpl`) also stores the DSN in plaintext
config and labels it "stored in plain text".

Fix: redact credentials before printing (`u.Redacted()` from `net/url`), and never include the raw
DSN in error messages.

### F6 — Medium — Download-cap / one-time-file enforcement is not atomic across instances (Inherited design; worsened by Postgres)

`internal/storage/FileServing.go:623-639`
```go
apimutex.Lock(apimutex.TypeMetaData, file.Id)
if recheckExpiry { ... file.DownloadsRemaining = database.GetDownloadsRemaining(file.Id) ... }
if increaseCounter {
	file.DownloadsRemaining = file.DownloadsRemaining - 1
	database.IncreaseDownloadCount(file.Id, !file.UnlimitedDownloads)
	...
apimutex.Unlock(...)
```
`apimutex` is an in-process mutex. The DB decrement is atomic within a statement
(`postgres/metadata.go:169-177`), but the **read → expiry-check → decrement** critical section that
enforces "downloads remaining" is guarded only per-process. The Postgres provider exists precisely
to allow a shared DB behind multiple Gokapi instances; in that topology two instances can each pass
the `DownloadsRemaining >= 1` check and both serve the file, so a "one-time" confidential file is
delivered more times than authorized. Separately, the decrement has no floor
(`DownloadsRemaining = DownloadsRemaining - 1`, no `WHERE DownloadsRemaining > 0`), so the column
can go negative.

Refutation attempt: is multi-instance actually intended? It is the standard reason to switch from
SQLite to Postgres, and nothing in the code prevents it. Even single-instance, the missing SQL-side
floor is a latent bug. Confirmed as a real gap for the shared-DB use case.

Fix: enforce the limit in SQL — e.g. `UPDATE ... SET DownloadsRemaining = DownloadsRemaining - 1
WHERE Id = $1 AND DownloadsRemaining > 0` and treat `RowsAffected()==0` as "denied". Do not rely on
a process-local mutex for a correctness-critical, cross-instance invariant.

### F7 — Low — Upsert conflict-target drift can panic where SQLite silently replaced (Introduced)

The Postgres upserts target the primary key only, e.g. `SaveHotlink`
(`postgres/hotlinks.go:54-56`, `ON CONFLICT (Id)`), but `Hotlinks.FileId` is **also** `UNIQUE`
(`Postgres.go:163`). SQLite's `INSERT OR REPLACE` (`sqlite/hotlinks.go:52`) deletes any row that
collides on *any* unique constraint before inserting; Postgres `ON CONFLICT (Id)` only handles an
`Id` collision and raises a unique-violation (→ `helper.Check` panic, F3) if the new row collides on
`FileId`. The same asymmetry exists for `ApiKeys.PublicId`/`UploadRequestId` and `Users.Name`
(a rename onto an existing name errors in Postgres vs clobbers the other user in SQLite). Postgres's
refusal is arguably *safer*, but it surfaces as a 500/panic rather than a handled error, and it is a
behavioural divergence from the reference implementation that tests may not cover.

Fix: decide the intended semantics explicitly. Where replace-on-secondary-key was relied upon,
delete-then-insert or add the correct `ON CONFLICT` target; otherwise convert the unique violation
into a handled error instead of a panic.

### F8 — Low — `uint64` traffic counter into signed `BIGINT` (Introduced)

`Statistics.Value` is `BIGINT` (signed, max 2^63−1) at `Postgres.go:198`, while the traffic counter
is `uint64` (`postgres/statistics.go:14,29`). `SaveStatTraffic` passes a `uint64`; pgx rejects
values above `math.MaxInt64`, so an insert would fail (→ panic) once cumulative traffic exceeds
~8 EiB. `GetStatTraffic` scans a signed column back into `uint64`, fine for all in-range values.
Purely theoretical at that scale; noted for completeness and parity with the "traffic counter into
BIGINT" concern raised in the brief.

Fix: none required in practice; if desired, use `NUMERIC` or clamp.

### F9 — Info — Spurious empty `E2EConfig` rows on migration (Inherited)

`internal/configuration/database/Database.go:83-86` calls
`SaveEnd2EndInfo(dbOld.GetEnd2EndInfo(user.Id), user.Id)` for every user, even those with no E2E
config, gob-encoding an empty struct and creating a row. Harmless (decodes back to empty) but
clutters the table and slightly muddies "who has E2E configured" analytics.

---

## 4. Explicitly checked and found clean

- **SQL injection (Postgres provider): none.** Every value is a bound parameter (`$1..$n`). The only
  string concatenation is with *static* column-list/table constants (`apiKeyColumns`,
  `metaDataColumns`, `fileRequestColumns`, `userColumns`) and a two-way static switch in
  `getUserWithConstraint` (`postgres/users.go:56-62`) — no request data reaches a query string.
- **`rows.Err()` handling: improved over SQLite.** Postgres adds `helper.Check(rows.Err())` to all
  five row-iterating methods; the SQLite provider has **zero** such checks. (Verified by grep.)
- **`UpdateUserLastOnline`: fixed.** SQLite passes 3 args to a 2-placeholder query
  (`sqlite/users.go:102`, latent driver-dependent bug); Postgres is correct
  (`postgres/users.go:120-122`).
- **`syncUserIdSequence` (identity resync): correct.** `GENERATED BY DEFAULT AS IDENTITY` does not
  advance on explicit-Id inserts; `setval(pg_get_serial_sequence('users','id'),
  GREATEST(COALESCE(MAX(Id),1),1))` (`postgres/users.go:112-116`) resyncs after update/migration.
  Called only on the update path (never for `isNewUser`), so natural sequence growth for new users
  is untouched. The empty-table edge (would skip Id 1) is unreachable because it runs only after an
  explicit-Id row exists.
- **Nullable handling: correct.** `ApiKeys.Expiry`/`IsSystemKey` via `sql.NullInt64`
  (`postgres/apikeys.go:19-20, 33-34`), `Users.Password` via `sql.NullString`
  (`postgres/users.go:17, 25-27`). `GetAllApiKeys` even improves the filter to include
  `OR Expiry IS NULL` (`postgres/apikeys.go:49`).
- **Upsert column coverage: complete.** Every `ON CONFLICT DO UPDATE` sets all non-key columns from
  `EXCLUDED`, matching the `INSERT OR REPLACE` field lists (metadata, apikeys, sessions,
  filerequests, users, e2econfig, statistics, schemaversion all cross-checked).
- **`IncreaseDownloadCount`: atomic per statement**, identical semantics to SQLite (the cross-
  instance/floor concern is F6, a design issue, not a drift).
- **Encryption core (server-side levels 1–4): sound.** Each file gets a fresh random data key
  (`Encryption.go:226 getRandomData`) and is streamed under it via `sio-go`/AES-GCM; the fixed
  all-zero *stream* nonce (`Encryption.go:156,168,196,…`) is safe because the per-file key is unique
  (no key+nonce reuse). The data key is then wrapped under the master cipher with a **random** nonce
  (`Encryption.go:226-232`). The zero-nonce master-key-in-RAM wrap (`Encryption.go:134,141`) encrypts
  exactly one value per startup key. No nonce-reuse vulnerability found in the server-side path.
- **Filename path traversal:** on-disk blobs are named by server-computed `SHA1`
  (`FileServing.go:73,778`), not by user input; download filenames go through `SanitiseFilename`
  (`helper/StringGeneration.go:77-97`, strips path separators/control chars/leading dots). No
  traversal found. (SVG hotlink XSS was addressed upstream at scheme v14; carried in schema notes.)
- **CSRF/session token generation:** `helper.GenerateRandomString` uses `crypto/rand`
  (`helper/StringGeneration.go:8,16-19`); session IDs are 60 chars, CSRF 20. Adequate entropy.
- **API key comparison timing:** lookup is an indexed `WHERE Id = $1` (not a byte compare in Go);
  keys are 30+ random chars — timing attack impractical. Inherited, not a concern.

---

## 5. Open questions / not determinable statically

1. **Multi-instance deployment?** F3 and F6 severities hinge on whether the company runs more than
   one Gokapi instance against the shared Postgres. If they will (the usual motivation), both are
   High; if strictly single-instance, F6 drops to Low and F3 stays High (network fragility remains).
   Needs a deployment-topology answer.
2. **Does the HTTP stack recover per-request panics, and are background-goroutine panics handled?**
   `go database.UpdateUserLastOnline(...)` and `go sse.PublishDownloadCount(...)` panic with no
   recovery under F3; confirm at runtime whether these actually crash the process (static reading
   says yes).
3. **`realSize` accounting abuse (F2):** what does the server do with the attacker-controlled
   `realSize` beyond display (quotas? traffic stats?) — needs a dynamic trace to rate the impact.
4. **pgx `uint64` boundary (F8):** exact driver behaviour at `> MaxInt64` (error vs wrap) was not
   executed; assumed error from pgx v5 source. Confirm only if exabyte-scale counters are plausible
   (they are not).
5. **Backup/replica exposure (F4):** whether the managed Postgres encrypts at rest and who can read
   backups is an operational question outside the code.
