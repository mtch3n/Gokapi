# PLAN — Gokapi fork: server-side encryption for a temporary file exchange

Branch: `gojitech-fork`.

Sections about the G1 decision and delivered items were removed on 2026-09-02;
delivered items are marked with their commit. Sections 1, 3 and 6 were removed
in that pass; the surviving sections kept their original numbers (2, 4, 5) so
existing cross-references elsewhere would not need renumbering.

Product: self-hosted TEMPORARY file exchange (send-to-client, client-upload-to-us,
internal exchange) for a Canadian healthcare-adjacent company (PIPEDA, HIPAA-adjacent).
Google Drive remains storage of record; nothing may linger here.

---

## 2. Phased work plan

Rules: after every item the full baseline must pass — `go generate ./...` then
`go test ./... -parallel 8 -count=1` with `--tags=test,noaws`, `--tags=test,awsmock`,
and `--tags=test,noaws,integration` (the suite now spans 66 test packages; Postgres
tests need `GOKAPI_TEST_POSTGRES_URL` against container `gokapi-test-pg` on
127.0.0.1:15432; setup tests bind port 53849 and other packages bind 53843-53848,
so the default port 53842 stays free for a dev server). Each phase ends with a
product that works end to end.

**Build-vs-buy/borrow rule (applies to every item):** prefer an established library or
managed service over hand-written code; prefer dependencies already in `go.mod`
(`golang.org/x/crypto v0.54.0`, `pgx/v5`, `go-oidc/v3`, `sio-go`, `caarlos0/env`,
stdlib `crypto/*`) over new ones; and design for **later extraction to
Forceu/Gokapi** — per Q7 (decided): build ours first, no upstream PRs now, upstream
one concern at a time once the deployment works. Every work item below carries an
explicit *Build vs. buy/borrow* line; a bespoke implementation must justify why the
alternatives do not fit.

**Commit-hygiene rule (Q7, applies to every item):** each work item lands as its own
commit or a small, clearly-scoped series — never batched with unrelated changes — so
any commit can later be cherry-picked into an upstream PR with minimal surgery.
Where an item mixes upstreamable and company-specific changes it MUST be split into
separate commits (called out explicitly on W15 — sink abstraction vs Azure backend —
and W21 — generic hashing mechanism vs local policy). No history rewriting or
squashing on this branch: traceability is the goal, and small single-purpose commits
also rebase onto upstream security patches far more cleanly (see W19). The
*Upstreamable* line on each item now means "extractable later", not "PR now". The
AGPL §13 source offer is independent of upstreaming and remains in W12 regardless.

### Phase 1 — Decision-independent correctness & non-retrofittable capture

Everything here is valuable at any encryption level. W7 leads in priority: audit
events not captured now are unrecoverable later, whereas every other compliance
layer can be added afterwards.

**W7 — Audit event coverage + forward-compatible record format [decision-independent]**
- *STATUS: delivered in `46163c1` + `c68c354`.*
- *Why:* **Event capture cannot be retrofitted.** An access that happens unrecorded
  is gone permanently; every other part of the compliance stack (policies,
  retention, signing, immutability, attestations) can be layered later onto events
  already held. Per the user's scope clarification, formal PIPEDA/HIPAA work is
  deferred, but the design must not foreclose auditability — so W7 is near the
  front and W15/W16 (signing/sinks/verifier) move later.
- *Non-retrofittable design decision — the record format is designed once,
  correctly, in this item:* every event is written from day one as canonical JSON
  with `version`, strictly monotonic `seq`, `prevHash`, and
  `hash = SHA-256(prevHash || canonical entry)` — i.e. the **chain exists from the
  first deployed event**, even though nothing signs it yet. W15 later adds signed
  checkpoints *over the already-formed chain* with no migration and no
  re-canonicalisation. Recommendation (requested): **start the chain at first
  deployment, not at a later cutover** — it costs one SHA-256 per event now, and
  when the first W15 checkpoint signs the head, all prior history becomes protected
  against tampering *from that moment on*. Stated honestly: events written before
  the first signed checkpoint could have been rewritten before that checkpoint;
  signing later cannot retroactively prove they were not. That residual window is
  the accepted cost of deferring W15.
- *Durability (Q8(a), decided — fail closed, best practice shape):* for guarded
  operations (downloads, uploads, denials) the event is appended to the local
  chained JSONL and **fsync'd before the response body is served** — commit the
  record, then serve the bytes, so a crash between the two over-logs (a recorded
  download that may not have completed: the safe direction) and never serves
  unrecorded content. Note this reverses today's fire-and-forget
  `go writeToFile(...)` (`Logging.go:349-359`) for audit events; the human-readable
  `log.txt` stays async. A failed local write refuses the operation (503). Remote
  shipping is *not* on the hot path — that is W15's spool.
- *HIPAA context (deferred, kept in mind):* §164.312(b) expects a record of PHI
  access activity — the event list below is chosen so that record exists when the
  compliance project starts.
- *What exists (reviewed — the complete `func Log*` inventory of
  `internal/logging/Logging.go:232-341`):* flat text file `config/log.txt`
  (`Logging.go:22, 37-39`), admin-viewable at `/logs` (`Webserver.go:121`), optional
  stdout mirror (`LOG_STDOUT`, `Environment.go:46`). Recorded today:
  - download *requested*: filename, file ID, user agent, IP iff `SaveIp`
    (`Logging.go:280-286`; hooks `FileServing.go:642` and zip `:729`; hotlink
    downloads pass through the same `ServeFile` hook);
  - upload: file + acting user, incl. file-request (guest) attribution — i.e.
    "file-request consumed" is covered (`Logging.go:295-301`);
  - edit / replace / delete / restore with acting user (`Logging.go:304-337`);
  - file-request created / edited / deleted with acting user (`Logging.go:309-322`);
  - login success (username only) and failure (username + IP) (`Logging.go:270-277`);
  - user created / edited / deleted (`Logging.go:252-267`); setup re-run and
    deployment-password change (`Logging.go:242-249`).
- *Precise gaps to close:*
  1. **Denied download attempts** — wrong file password (`Webserver.go:591-611`) and
     exhausted/expired link (the W2 "denied" branch; also
     `redirectOnIncorrectId` paths) produce no log entry;
  2. **API key lifecycle** — no `Log*` call exists for API key creation, deletion, or
     permission change (absent from the function inventory above);
  3. **Automatic expiry/disposal** — `CleanUp` (`FileServing.go:813-852`) deletes
     blobs and metadata without logging, so disposal cannot be evidenced;
  4. **Encryption/config changes** — only a generic "Re-running Gokapi setup"
     (`Logging.go:242-244`), with no record of *what* changed (e.g. encryption level);
  5. **Download identity** — anonymous-share downloads are inherently unattributable
     (by design); admin/API-authenticated downloads could carry the user but do not;
  6. **Logout** — not logged (minor).
- *Design:* route all audit-relevant events through one internal structured-event
  function (JSON: seq-ready fields — timestamp, category, action, file ID, actor or
  "anonymous-share", request ID, outcome as success/failure/denied, IP per below;
  adopted from the yopass audit field set after comparison: authenticated identity
  where present as user id + email + OIDC subject (available from the session and
  `go-oidc` claims), the file's configuration metadata at event time
  (one-time/remaining downloads, expiry, password-protected), and an error
  description on failures — and, explicitly, never file content or secrets) that
  (a) keeps writing the
  human-readable `log.txt` + stdout exactly as today and (b) is the single seam W15's
  chained sink attaches to. Add the six missing event types above. Follow the OWASP
  Logging Cheat Sheet exclusions: never log passwords, session cookies, API-key
  secrets, or file passwords (current code already complies — keep it that way in
  review).
- *IP logging (Q2 — DECIDED: yes, with PIPEDA controls):* IPs are personal
  information; the controls are part of this item, not optional:
  1. **Coverage check (verified):** the existing `SaveIp` config flag
     (`models/Configuration.go:24`, set in the wizard) gates IPs **only** on
     `LogDownload` (`Logging.go:280-286`); failed logins always log IP
     (`Logging.go:270-272`); uploads log **no** IP (`Logging.go:295-301`). So
     `SaveIp` does *not* cover what W7 needs — extend IP capture (gated on the same
     flag, set true) to upload events and to all new denied-attempt events, via the
     existing proxy-aware `logging.GetIpAddress` (`Logging.go` + `TRUSTED_PROXIES`).
  2. **Truncation/hashing analysed, rejected:** truncating to /24 or salted-hashing
     IPs defeats the stated purpose (incident investigation and abuse attribution —
     correlating an event with a specific client/session needs the exact address;
     salted hashes can't be compared against firewall/App Service logs). Full IP is
     logged, with the compensating controls being disclosure + retention + access
     control, and this analysis is the documented justification (purpose
     limitation).
  3. **Disclosure:** a short privacy notice on the public download, upload-request
     and password pages stating that IP, timestamp and file identifiers are recorded
     for security purposes and how long they are kept — delivered via the W10
     `custom` mechanism or a template string; W12 owns the wording.
  4. **The audit log is now a PI repository:** access-restricted (already in W15's
     privacy section), retention-limited (Q8(b)), and in scope for data-subject
     access/deletion procedures documented in W12 — including the documented
     immutability carve-out (PIPEDA permits retention needed for security purposes;
     the notice says so).
- *Touches:* `internal/logging/Logging.go` (new event types + structured emitter +
  IP plumbing); hooks in `internal/storage/FileServing.go` (W2 denial, `CleanUp`
  disposal), `internal/webserver/Webserver.go` (password fail),
  `internal/webserver/api/Api.go` (API key lifecycle),
  `internal/configuration/setup/Setup.go` (config-change detail); templates for the
  privacy notice.
- *Effort:* L (raised from M per Codex; the six event types, the chained durable
  writer, IP plumbing and the notice are each small but numerous). *Risk:* low —
  additive. *Deps:* W2 (denial hook).
- *Upstreamable:* yes — better audit coverage is generically useful; per Q7, land
  the event-coverage commits separately from the chained-writer commit so each
  extracts cleanly.
- *Build vs. buy/borrow:* stdlib `encoding/json` + existing logging plumbing. A full
  logging framework (zap/zerolog/slog re-plumb) was considered and rejected: the event
  volume is tiny and the goal is auditability, not throughput; stdlib `log/slog` may be
  used for the structured emitter since it is already in the standard library.
- *Acceptance:* each of the six gap events produces exactly one structured entry with
  the fields above incl. outcome, identity-when-authenticated and config metadata
  (integration test per event); a failed password attempt and an exhausted-link
  attempt are visible in `/logs` with an error description; no secret material or
  file content appears in any entry (grep assertion in test).

**W2 — Atomic, floored, cross-instance download-cap enforcement (F6) [decision-independent]**
- *STATUS: delivered in `1ae6e19`.*
- *Why:* "One-time link" is a product promise for confidential data; today it breaks
  across instances and the counter can go negative.
- *Status under Q4 (decided: single instance for now):* no longer a **launch**
  blocker, but kept as a correctness fix in Phase 1 because the floor bug exists even
  single-instance and the fix is cheap. Stated plainly: **scaling past one instance
  without W2 silently breaks one-time links.** The W8 scale-out checklist records
  this plus the other per-instance components.
- *Design:* make the decrement the gate. Replace the unconditional
  `IncreaseDownloadCount(id, decrease)` with a conditional SQL decrement that returns
  whether it won: `UPDATE FileMetaData SET DownloadCount = DownloadCount + 1,
  DownloadsRemaining = DownloadsRemaining - 1 WHERE Id = $1 AND DownloadsRemaining > 0`
  and treat `RowsAffected() == 0` as "denied" (serve the expired page). Keep the
  apimutex as a local fast-path only.
- *Touches:* `internal/configuration/database/provider/postgres/metadata.go:169-177`;
  `internal/configuration/database/provider/sqlite/metadata.go:154-163`; the redis
  provider's equivalent; the `dbabstraction` interface and `database.IncreaseDownloadCount`
  (`internal/configuration/database/Database.go`); caller
  `internal/storage/FileServing.go:623-641` (`ServeFile` must consult the return value
  before writing the body; today it decrements *after* deciding to serve);
  `FileServing.go:957-960` (`IsExpiredFile` semantics unchanged).
- *Effort:* M. *Risk:* medium — touches the hot serving path and the provider interface
  (42 methods, three backends); zip/presigned paths call `ServeFile` with
  `increaseCounter=false` (`Webserver.go:1066`, `Api.go:629-631`) and must keep their
  semantics.
- *Deps:* none. *Upstreamable:* yes — upstream already fixed the single-process race
  (`c2880b7`); this completes it for shared DBs and fixes the negative counter.
- *Build vs. buy/borrow:* the "existing solution" is the database itself — one atomic
  conditional `UPDATE ... WHERE DownloadsRemaining > 0` + rows-affected (Postgres and
  SQLite both guarantee per-statement atomicity). Explicitly rejected: Redis
  distributed locks, lease/leader-election packages — added moving parts for a
  property plain SQL already provides. The Redis provider keeps working via its
  existing atomic primitive (`DECR`-style, or `WATCH`/Lua if a floor is needed —
  smallest change that preserves the semantics).
- *Acceptance (corrected per Codex):* the original wording — "two provider instances
  driving two concurrent `ServeFile` calls" — is not expressible in one process,
  because `ServeFile` uses the package-global database installed by
  `database.Connect` (`internal/configuration/database/Database.go:16-25`). Split the
  test: (a) **provider-level concurrency test** — two directly-instantiated
  `postgres.DatabaseProvider` values against the shared test Postgres race the new
  conditional decrement on a `DownloadsRemaining=1` row, exactly one wins,
  never negative, 100 iterations; (b) **single-process serving test** — `ServeFile`
  on an exhausted file returns the denied path and writes no body; (c) a true
  two-process double-download smoke test is deferred to the W8/W20 staging
  environment (and is only mandatory before any future scale-out per Q4).

**W23 — Presigned and zip downloads bypass download-limit accounting [decision-independent]**
- *Why (found while reviewing W2, verified):* W2 made the decrement atomic, but two
  paths never decrement at all, so the cap they enforce can simply be walked around.
  `Webserver.go:1066` serves a presigned download with `increaseCounter=false`, and
  `createAndOutputPresignedUrl` (`Api.go:684`) does not decrement either, so a
  presigned URL for a one-time file can be fetched repeatedly. `ServeFilesAsZip`
  (`FileServing.go:874`) itself contains no reference to `IncreaseDownloadCount` — it
  only serves what it is handed. **Partly addressed since:** the public folder-zip path
  now consumes the bundle allowance before touching any member counter
  (`Webserver.go` ~1975-2043), so that path is covered. The admin `/files/downloadzip`
  route and the presigned-URL path still call `ServeFilesAsZip` (or serve the presigned
  file) without ever touching a counter, so the hole remains open there. This is
  pre-existing upstream behaviour on the two still-open paths, not something W2
  introduced, but it punches a hole in exactly the product promise W2 exists to
  protect: a "limit 1" link is not actually limited on those two paths.
- *Urgency:* presigned URLs are an S3 feature and the deployment is on local storage for
  now, so this is not currently reachable in production. It becomes live the moment S3
  or S3Proxy is adopted, which is on the roadmap. The zip path may be reachable sooner —
  check whether the UI offers multi-file download on local storage.
- *Design:* decide the intended semantics first, because they are genuinely debatable.
  Should generating a presigned URL consume the download, or should fetching it? Should
  a zip of five files consume five allowances or one? Write the answer down before
  coding; a plausible-looking guess here silently changes what a share means.
- *Touches:* `internal/webserver/Webserver.go`, `internal/webserver/api/Api.go`,
  `internal/storage/FileServing.go` (`ServeFilesAsZip`), plus `presign`.
- *Effort:* M. *Risk:* medium — changes user-visible sharing semantics.
- *Deps:* W2 (uses the atomic primitive it added). *Upstreamable:* yes.
- *Build vs. buy/borrow:* reuses W2's atomic decrement; nothing external applies.
- *Acceptance:* a one-time file fetched twice through a presigned URL is refused the
  second time; a zip download consumes the agreed number of allowances; unlimited-
  download files are unaffected on both paths.

**W3 — Server-authoritative rejection of the `isE2E` upload flag (F2) [decision-independent]**
- *STATUS: delivered in `313d719`.*
- *Why:* Prevents mislabelled "end-to-end encrypted" files, ciphertext-garbage
  downloads, and dedup bypass under server-side encryption.
- *Design:* if `configuration.Get().Encryption.Level != encryption.EndToEndEncryption`,
  reject any upload asserting E2E with HTTP 400 (do not silently strip — fail closed and
  visible).
- *Touches:* `internal/webserver/fileupload/FileUpload.go:180-188` (`parseConfig`);
  `internal/webserver/api/routing.go:682, 690-698` (`paramChunkComplete`);
  `internal/webserver/api/Api.go:483-502` (`apiChunkComplete`); possibly
  `fileupload.CreateUploadConfig` (`FileUpload.go:133-149`) as the single choke point,
  mirroring how `fcb5ed3` placed `applyMaxExpiry` there.
- *Effort:* M (raised from S per Codex — the natural choke point
  `CreateUploadConfig` returns only `models.UploadParameters`, so rejecting requires
  either changing its signature to return an error through all callers
  (`FileUpload.go:133`, `Api.go:488, 722`) or validating in each of the three entry
  points; the signature change is preferred and touches more call sites than a
  one-liner). *Risk:* low; E2E-at-E2E-level behaviour unchanged.
- *Deps:* none. *Upstreamable:* yes (bug even upstream: asserting `isE2E` at levels 0-4
  corrupts serving).
- *Build vs. buy/borrow:* pure server-side validation against existing config; no
  library applicable. Upstream PR is the "borrow" move — once merged, the fork carries
  nothing.
- *Acceptance:* unit test — at level `FullEncryptionStored`, form upload with
  `isE2E=true` and API chunk-complete with header `isE2E: true` both return 400 and no
  metadata row is written; at level `EndToEndEncryption` the flag still works.

**W4 — Kill automatic hotlinks, including existing ones (company policy) [decision-independent]**
- *STATUS: delivered in `7e134f1`.*
- *Why:* Every image upload silently gets a second, password-free, non-expiring-URL-style
  access path at `/h/<id>.<ext>` (`AddHotlink` called unconditionally from
  `createNewMetaData` at `FileServing.go:328` and `DuplicateFile` at
  `FileServing.go:440`; served at `Webserver.go:117-118, 630-647`). They do honour
  expiry and decrement the download counter (`ServeFile` with `increaseCounter=true`,
  `Webserver.go:640`), but a confidential-exchange product should not mint extra URLs.
- *Design:* new env var `GOKAPI_DISABLE_HOTLINKS` (default false upstream, set true in
  our deployment): `AddHotlink` returns early; `IsAbleHotlink` returns false, which blocks the re-add path in `apiEditFile`, which calls
  `IsAbleHotlink`/`AddHotlink` on every edit — `Api.go:121-126`).
  *Correction found in review:* this plan previously claimed `FileList.go:117-130` hides
  `UrlHotlink` via `IsAbleHotlink`. That is wrong — `models` cannot import `storage`, and
  `getHotlinkUrl` never consults it. Once `HotlinkId` is cleared the field falls back to the
  ordinary download URL keyed on the file's own `Id`, which is the same secret already
  published as `UrlDownload` and is password- and expiry-checked by `serveFile`. No extra
  access path survives, but the JSON field is not literally empty, so the acceptance wording
  below is satisfied in substance rather than literally. **Mandatory purge, not optional (corrected per Codex):**
  the regular `cleanHotlinks()` only deletes hotlinks whose file is already
  unavailable (`FileServing.go:903-912` — it checks `GetFileByHotlink` and removes
  only dead ones), so existing *valid* hotlinks would stay live indefinitely. When
  the flag is set, a startup migration must delete **all** hotlink rows and clear
  `HotlinkId` on their metadata.
- *Touches:* `internal/environment/Environment.go` (new field; note
  `build/go-generate/updateEnvVariables.go` runs in `go generate`);
  `FileServing.go:525-556`; startup purge (e.g. in `CleanUp` init or
  `cmd/gokapi/Main.go` after DB connect); docs.
- *Effort:* M (raised from S per Codex — the purge migration and its tests are real
  work). *Risk:* low. *Deps:* none. *Upstreamable:* yes — generic opt-out,
  consistent with existing `ENABLE_HOTLINK_VIDEOS` (`Environment.go:89`).
- *Build vs. buy/borrow:* env parsing via the in-tree `caarlos0/env` machinery and the
  existing `go generate` docs pipeline; nothing new. Upstream PR preferred.
- *Acceptance:* with the var set: uploading a `.png` yields empty `HotlinkId`, no
  `UrlHotlink` in the API JSON, `/h/<anything>` returns the expired-image SVG, a
  **pre-existing valid** hotlink is dead after restart (purge test), and an
  `apiEditFile` round-trip does not re-create one; without the var, upstream
  behaviour intact (existing tests pass).

**W5 — Test-lock the fresh-key-per-file invariant (zero-nonce safety) [decision-independent — the same code path serves E2E client crypto]**
- *STATUS: delivered in `1639eb1`.*
- *Why:* The all-zero stream nonce (`Encryption.go:156` et al.) is safe iff no file key
  is ever reused for different plaintexts. Nothing currently prevents a future
  refactor from reusing keys and silently creating catastrophic AES-GCM nonce reuse.
- *Design:* unit tests in `internal/encryption`: (1) two `Encrypt` calls produce
  distinct `encInfo.DecryptionKey`/`Nonce` and distinct ciphertexts for identical
  plaintext; (2) `generateNewFileKey` never returns a repeated key across N draws;
  (3) a loud comment at `Encryption.go:152-161` stating the invariant and pointing at
  the test. Also assert the dedup path (`copyEncryptionInfo`,
  `FileServing.go:180-193`) only ever pairs an existing key with the *existing
  ciphertext blob*, never re-encrypts new content under an old key.
- *Effort:* S. *Risk:* none (tests only). *Deps:* none. *Upstreamable:* yes.
- *Build vs. buy/borrow:* stdlib `testing` only. The alternative "borrow" would be
  switching to a nonce-managed AEAD scheme wholesale — rejected as a format break for
  zero present-day risk (cf. ChaCha20 NOT-DOING, §4).
- *Acceptance:* the new tests exist, pass, and fail if `generateNewFileKey` is stubbed
  to return a constant.

**W17 — Close the expiry-clamp hole on the edit path (completes `fcb5ed3`) [decision-independent]**
- *STATUS: delivered in `bd607ff` (superseded by `83f1c9c`).*
- *Why (Codex finding, VERIFIED):* `fcb5ed3` clamps every *creation* path via
  `CreateUploadConfig`, but `apiEditFile` lets any authorised editor set
  `file.UnlimitedTime = true` or an arbitrary `file.ExpireAt` afterwards with no
  clamp (`internal/webserver/api/Api.go:99-114`). "Nothing may linger" is
  therefore **not currently enforced end-to-end**, and the traceability row
  claiming it was done is corrected to point here. (`apiDuplicateFile` *is*
  clamped — it goes through `CreateUploadConfig`, `Api.go:722-729`; a duplicate
  without `ParamExpiry` copies the source's already-clamped expiry — assert both
  in tests.)
- *Design:* apply the `applyMaxExpiry` semantics (`FileUpload.go:171-183`) in
  `apiEditFile`: when `MaxExpiry > 0` (a duration, not a day count), reject-or-clamp
  `UnlimitedExpiry=true` and clamp `ExpiryTimestamp` to `now + max`. Export/reuse the
  existing helper — one policy, two call sites; align with W3's validation choke
  point if the signatures allow.
- *Touches:* `internal/webserver/api/Api.go:82-131`;
  `internal/webserver/fileupload/FileUpload.go` (export clamp helper); tests.
- *Effort:* S. *Risk:* low. *Deps:* none. *Upstreamable:* yes — it completes the
  `GOKAPI_MAX_EXPIRY` feature.
- *Build vs. buy/borrow:* reuse of the fork's own clamp helper; nothing external.
- *Acceptance:* with `GOKAPI_MAX_EXPIRY=720h` (30 days): `files/modify` with
  `unlimitedExpiry=true` yields expiry ≤ 30 days; an `ExpiryTimestamp` a year out
  is clamped; duplicate-with- and without-`ParamExpiry` both end ≤ 30 days.

**W18 — Session hardening: `Secure` cookie attribute + shorter lifetime [decision-independent]**
- *STATUS: DONE* (`7751262`, merged). `Secure` is gated on `configuration.UsesHttps()`, which
  is derived from `ServerUrl` rather than from a request header, so a TLS-terminating proxy
  only works correctly if `ServerUrl` is configured `https://` — W8 must pin this and W20
  must spot-check it. New `GOKAPI_SESSION_DURATION_DAYS`, default 7, confirmed by the user.
- *UPSTREAMING NOTE (review finding):* when this is extracted into an upstream pull request,
  split it. Upstream gets the `Secure` fix and the configurability knob with `envDefault:"30"`,
  preserving existing behaviour; our deployment sets `GOKAPI_SESSION_DURATION_DAYS=7`. Upstream
  maintainers are unlikely to accept a silent 30-to-7 change in default session lifetime, and
  this keeps W18 consistent with W4, which was deliberately specified to default to upstream
  behaviour. One-character change at PR time.
- *Why (Codex finding, VERIFIED):* `writeSessionCookie` sets `HttpOnly` and
  `SameSite=Lax` but **no `Secure` attribute**
  (`internal/webserver/authentication/sessionmanager/SessionManager.go:85-95`),
  and admin sessions live 30 days (`cookieLifeAdmin`, `SessionManager.go:17`).
  Cheap, structural, expensive to retrofit into audit narratives later.
- *Design:* set `Secure` when `configuration.UsesHttps()` (already used at
  `Webserver.go:577`); make session lifetime an env-configurable value defaulting
  well below 30 days (recommend 7; OIDC re-validation via `OAuthRecheckInterval`
  already exists, `Authentication.go:280`, so shorter cookies cost users little).
  **Proxied-TLS nuance (yopass precedent, verified against Gokapi):** yopass
  requires the reverse proxy to send `X-Forwarded-Proto: https` for its `Secure`
  cookies; Gokapi does NOT inspect `X-Forwarded-Proto` — `UsesHttps()` is derived
  from the configured `ServerUrl` prefix (`Configuration.go:81, 109-111`), not
  from the listener or proxy headers. So gating on `UsesHttps()` works behind the
  App Service TLS terminator **iff** `ServerUrl` is configured `https://` — W8
  pins that setting and W20 line 6 spot-checks the cookie attributes in staging.
- *Touches:* `SessionManager.go`; `Environment.go` (+generated docs).
- *Effort:* S. *Risk:* low (deploy logs everyone out once). *Deps:* none.
- *Upstreamable:* yes — the missing `Secure` flag is an upstream defect.
- *Build vs. buy/borrow:* stdlib `net/http` cookie fields; nothing external.
- *Acceptance:* `Set-Cookie` carries `Secure; HttpOnly; SameSite=Lax` under
  https; a session past the configured lifetime is rejected; unit tests.

### Phase 2 — Decision-independent platform, identity and hardening

> **Operational consequence of W7 that W8 and W20 must handle.** Audit writes are
> fail-closed, and startup recovery sets `auditChainUnusable` if a non-empty audit file
> has no entry that verifies, refusing every subsequent write. Combined, a fully
> corrupted audit file makes the instance answer **every download, upload and denial
> with 503** until an operator moves the file aside and restarts. The trigger is narrow
> — torn tails and mid-file tampering still recover to the last verifiable entry — but
> the escape hatch is currently **stdout only**: nothing surfaces in the admin UI or a
> health endpoint. W8 must document the operator procedure and alert on it; W20 should
> drill it. Consider surfacing the state on a health endpoint so the platform can see it.

**W8 — Azure App Service deployment profile [decision-independent, except the
master-key app setting which is Level-2-specific]**
- *Why:* Encode the constraints so the deployment is reproducible and its residual
  risks are written down.
- *Content:* container image (upstream `Dockerfile`); persistent mounts — `CONFIG_DIR`
  and `DATA_DIR` (`Environment.go:25-31`) on the App Service storage mount (SQLite
  explicitly NOT used there; metadata via `DatabaseUrl = postgres://...` with
  `sslmode=require`, enforced at `Setup.go:961-963`); `PORT` (default 53842,
  `Environment.go:16`); `TRUSTED_PROXIES` for the App Service front end
  (`Environment.go:80-84`; IP correctness feeds W7 logs);
  `GOKAPI_MAX_EXPIRY=<Q1 value as a duration, e.g. 720h for 30 days>`
  (`Environment.go:78`, enforcement `FileUpload.go:167-173`); `GOKAPI_DISABLE_HOTLINKS` (W4);
  `GOKAPI_ENCRYPTION_KEY_B64` as a Key Vault reference (W6); `LOG_STDOUT=true` (W7).
  Additions from the reconciliation: run the container **non-root** — the image runs
  as root unless `DOCKER_NONROOT=true` (deprecated mechanism, `dockerentry.sh:2-15`;
  the documented replacement is the container `--user` directive per the referenced
  migration doc) — use the supported user mechanism; Azure Monitor **alerts** on
  storage-mount usage (ceiling for anonymous-upload abuse), request-rate anomalies
  and container restarts; backup configuration feeding W20 (coordinated Postgres
  PITR + data-share snapshot + config + Key Vault secret backup); staff-facing
  defaults reflecting Q1's 30-day cap (per Q1's consequence note: default the upload
  form's `expiryDays` preset *below* 30 — recommend 7 — and small
  `allowedDownloads`, so 30 days is the ceiling, not the norm for leaked-link
  exposure).
  **Scale-out checklist (Q4 — single instance for now; this is the recorded list
  for later):** W2 merged (else one-time links silently break); per-instance
  in-memory state: `downloadstatus`
  (`internal/webserver/downloadstatus/DownloadStatus.go:10-27`), SSE upload status,
  processing status, the rate limiter store
  (`internal/webserver/ratelimiter/RateLimiter.go:38-44` — in-process maps), the
  hourly `CleanUp` timer (`FileServing.go:846-851`, kicked from
  `cmd/gokapi/Main.go:69` — idempotent but racy on dedup deletion across
  instances), and W7's audit `seq`/chain writer (single-writer assumption — needs a
  coordination design before >1 instance); ARR affinity for chunked uploads/SSE;
  re-evaluate the yopass-style read-only/admin-off split instance at that point
  (§4 row — the public write path for file requests limits its value today).
  **Documented residual risks:** chunk files (`DataDir/chunk-<uuid>`) and
  pre-encryption temp files (`os.CreateTemp(DataDir, "upload")`) hold plaintext on
  the data mount until assembly and encryption complete — accepted, no code change
  planned; Postgres TLS check runs at setup time only — an operator hand-editing
  `config.json` later bypasses it (accepted; config is operator-controlled).
- *Effort:* L (raised from M per Codex — IaC, alerts, backup wiring and non-root are
  real work). *Risk:* low. *Deps:* W4, W7; W6 only for the L2-specific app setting.
- *Upstreamable:* docs only.
- *Build vs. buy/borrow:* entirely managed services (App Service, Azure Files, Azure
  Database for PostgreSQL, Key Vault, Log Analytics); no custom code. Infra captured
  as Bicep/Terraform rather than portal clicks.
- *Acceptance:* clean deploy from the written profile; container restart requires no
  interactive input; files survive restart; a scale-to-2 test is explicitly deferred
  until W2 is merged.

**W9 — OIDC/SSO against Google Workspace + MFA posture [decision-independent]**
- *STATUS: superseded by the hybrid-auth work (`f111e52` through `af6ff24`).*
- *Why:* Admin access must be tied to the company IdP; MFA inherited from Google.
- *What exists (verified — this is configuration, not code):* full OIDC support via
  `github.com/coreos/go-oidc/v3` (`internal/webserver/authentication/oauth/Oauth.go:23-45`),
  wizard-configured provider/client/secret, `OnlyRegisteredUsers`
  (`internal/webserver/authentication/Authentication.go:254`), `OAuthGroups`
  (`Authentication.go:272-273`), `OAuthRecheckInterval` (`Authentication.go:65, 280`),
  routes `/oauth-login`, `/oauth-callback` (`Webserver.go:136-137`).
- *Plan:* provider `https://accounts.google.com`; set `OnlyRegisteredUsers=true` and
  pre-create the four internal users (Google's standard OIDC tokens do not carry a
  usable groups claim, so do not rely on `OAuthGroups`); short recheck interval;
  document that MFA is enforced in the Google Workspace admin console (Gokapi has no
  native TOTP — the fallback local admin password remains for break-glass only, long
  random, stored in the team vault).
- *Effort:* M (raised from S per Codex — real staging verification against Google,
  redirect-URI and recheck-interval testing, break-glass documentation). *Risk:*
  low; `5d1014f`/`66ff9e6` show OIDC is actively maintained
  upstream. *Deps:* W8 (needs the real public URL for the redirect URI).
- *Upstreamable:* n/a (config).
- *Build vs. buy/borrow:* borrow everything — `go-oidc/v3` is already in the tree and
  wired; identity and MFA are bought from Google Workspace. No auth code is written.
- *Acceptance:* login via Google works for a registered user, is rejected for an
  unregistered Workspace user; token recheck logs out a disabled user within the
  recheck interval.

**W10 — Branding via the `custom/` mount [decision-independent] [NEVER UPSTREAMED]**
- *User direction, 2026-08-27:* theme and UI work will **not** be merged upstream and no
  pull request will ever be raised for it. It is permanently ours.
- *Consequence, and it is a good one:* this should therefore live **entirely outside the
  fork**, in the deployment's `custom/` mount (`~/Work/filedrop/custom/` — `custom.css`,
  `public.js`, `admin.js`, `favicon.png`, `version.txt`), which the server already serves
  from `/custom/` and the templates already include. Branding then costs the fork **zero
  divergence**: no Go change, no template change, nothing to rebase, nothing to carry.
  That directly helps the upstream-patch tracking problem in W19, since every remaining
  commit in the fork stays extractable.
- *Hard rule:* if something genuinely cannot be done through `custom/` and needs a
  template or Go change, it goes in its own clearly-labelled commit that is never
  included in any upstream extraction — do not mix it into a commit that is otherwise
  upstreamable. Prefer changing the requirement over creating that divergence.

- *Why:* Client-facing pages must look like the company, not Gokapi.
- *Mechanism (verified):* mount `custom/` next to the executable (`/app/custom/` in
  Docker) with `custom.css`, `public.js`, `admin.js`, `favicon.png`, `version.txt`
  (`docs/advanced.rst:605-621`; loaded by `loadCustomCssJsInfo` and injected into all
  templates via `customStaticInfo`, `Webserver.go:85-86, 100`; the download template
  includes `{{ template "customjs" . }}` at `html_download.tmpl:186`). Only Go/template
  changes require the fork.
- *Effort:* S (CSS/asset work). *Risk:* none. *Deps:* W8 (mount). *Upstreamable:* n/a.
- *Build vs. buy/borrow:* use the stock binary's `custom/` mechanism exclusively; a Go
  fork for branding is explicitly rejected — it would add permanent merge burden for
  something the upstream extension point already covers.
- *Acceptance:* download page, file-request upload page, and login page show company
  branding from a mounted folder on the stock binary; no template diffs against
  upstream needed.

**W21 — Hash session tokens and API keys at rest, behind a credential seam (Q5, DECIDED) [decision-independent]**
- *Why (VERIFIED):* a database read today yields live bearer credentials: the
  session cookie value is the `Sessions` primary key
  (`postgres/sessions.go:22`), the API key secret is the `ApiKeys` primary key
  looked up via `WHERE Id = $1` (`postgres/apikeys.go:67`), and the Redis
  provider embeds both **inside key names** (`redis/apikeys.go:12-36`,
  `redis/sessions.go:27-29`). Hashing at rest turns a DB/backup compromise from
  "full impersonation" into "nothing usable".
- *Pros / cons (requested):* **pro** — stolen DB, replica, backup or log dump no
  longer authenticates anyone; removes the F4 residual. **con** — diverges from
  upstream schema v15 (fork schema bump + migration, ongoing merge cost until/
  unless upstreamed); API keys become show-once in the UI; Redis key-space
  migration; touches the auth hot path (medium risk).
- *Hash choice (per decision guidance):* SHA-256, **not** bcrypt/argon2 — these
  are 30+ character `crypto/rand` tokens (`helper/StringGeneration.go:8-19`),
  not low-entropy passwords; key-stretching buys nothing and would add
  deliberate latency to every authenticated request. Flow becomes
  hash-then-lookup: the digest is the stored key, preserving **indexed
  single-row lookup** in all three providers — this is a hard interface
  requirement (any design forcing a scan over all sessions/keys is rejected).
  Redis keys become `apikey:<hex(sha256)>` / `session:<hex(sha256)>` — verified
  compatible: the provider only round-trips the id string in key names.
- *Credential seam (user architectural note, incorporated):* do NOT sprinkle
  `sha256.Sum256` through providers and middleware. Introduce one
  `CredentialStore`/`TokenHasher` interface — "presented token → lookup key +
  verification" policy lives in exactly one place, mirroring `dbabstraction` and
  the W15 `AuditSink`. One default implementation (SHA-256). The seam, as
  designed, accommodates: a keyed MAC (HMAC with a Key Vault key — swap the
  implementation, same lookup shape, and a stolen DB can then not even *confirm*
  a guessed token); sessions delegated to an external store (the interface takes
  a token and returns a principal — storage lives behind it); IdP-issued or
  scoped/expiring API tokens (verification is implementation-owned; `go-oidc` is
  already in-tree, so IdP-verified credentials are a realistic swap); an
  external verifier service or plugin. **None of these alternatives is built
  now** — one default only. Cost of the seam over inline hashing: near zero (one
  interface, one struct; every call site must be touched either way), so the
  flexibility is essentially free — stated per instruction.
- *Cutover (corrects an assumption in the decision):* existing stored values ARE
  the plaintext tokens, so the one-time migration simply rewrites each stored
  id to its digest — **existing sessions and API keys keep working**; what is
  irreversibly lost is *re-display*: the admin UI can no longer show an existing
  key's secret. UI switches to listing by the existing `PublicId`
  (`ApiKeys.PublicId`, unique — `postgres/Postgres.go:122` region) with the
  secret shown **once** at creation (exact current template behaviour in
  `html_api.tmpl` to be confirmed during implementation).
- *Touches:* new `internal/webserver/authentication/credentials/` (seam +
  SHA-256 impl); `sessionmanager/SessionManager.go`; API-key auth path in
  `api/Api.go`; migration + schema bump for sqlite/postgres/redis providers; API
  admin UI templates/JS.
- *Effort:* L. *Risk:* medium (auth hot path; mitigated by the migration keeping
  tokens valid and by full test-suite coverage). *Deps:* none hard; land before
  go-live. *Upstreamable:* the generic seam + hashing plausibly yes; per Q7 the
  generic mechanism and any local policy land in **separate commits**.
- *Build vs. buy/borrow:* stdlib `crypto/sha256`; the seam is the borrow-enabler
  (lets a future plugin/IdP mechanism replace it wholesale).
- *Acceptance:* DB rows and Redis keys contain no usable bearer material (test
  authenticates with a raw stored value and MUST fail); login and API calls work
  across the migration without re-issuing; creation shows the secret exactly
  once; performance: auth adds ≤ 1 digest per request (no measurable latency in
  the integration suite).

### Phase 3 — Encryption-dependent build (server-side encryption, per G1)

G1 was decided 2026-08-31 for server-side encryption (FullEncryptionStored /
FullEncryptionInput; production runs Level 4). This phase builds W6 and W11
against that decision.

**W6 — Master key from an external secret source + dual-key rotation (Azure Key Vault via env var) [server-side-encryption-specific, per G1]**
- *Why:* Highest-value compliance item and the replacement for the cancelled sealed-box
  work. Today the choice is: key in `config.json` on the same Azure Files share as the
  ciphertext (`models/Configuration.go:29-35`; `Setup.go:644-651` generates it), or a
  passphrase supplied at runtime through POST `/api/unseal` (`encryption.Unseal`,
  `Encryption.go:174`), which keeps the key off disk but needs an operator action
  after every restart. Neither is defensible for PHI-adjacent data.
- *Design (simplest full solution):* support a new env var, e.g.
  `GOKAPI_ENCRYPTION_KEY_B64` (base64 of 32 bytes). If set at a `FullEncryptionStored`/
  `LocalEncryptionStored` level, `encryption.Init` (`Encryption.go:52-63`) uses it via
  `initWithCipher` (`Encryption.go:121-126`) **instead of** `config.Encryption.Cipher`,
  and setup never persists a cipher to `config.json` when the var is present. On Azure,
  the App Service app setting is a **Key Vault reference**
  (`@Microsoft.KeyVault(SecretUri=...)`), so Key Vault integration costs zero Azure SDK
  code, works with managed identity, is audited by Key Vault access logs, and the same
  mechanism serves any other secret store (plain env var) for non-Azure users — which is
  exactly what makes it upstreamable. Setup wizard: allow generating the key and
  printing it once for vault storage, or accepting "provided externally".
- *Touches:* `internal/encryption/Encryption.go:52-63`;
  `internal/environment/Environment.go` (+ generated docs);
  `internal/configuration/setup/Setup.go:614-668` (don't generate/persist cipher when
  externally supplied; validation); startup error path if var missing/malformed at a
  level that needs it (fail fast with a clear message, since all files become
  unreadable otherwise).
- *Key rotation (Q3 — analysis and recommendation, as requested):* today, "rotation"
  is destruction: every per-file key is AES-GCM-wrapped under the master key
  (`Encryption.go:221-238`), and the setup wizard's answer to a key change is to
  delete all encrypted storage (`Setup.go:640-651`). Two real designs:
  **(a) re-wrap migration tooling** — walk all metadata, unwrap each
  `Encryption.DecryptionKey` with the old master key, re-wrap with the new one
  (file ciphertext untouched; only the small wrapped blob and nonce change); needs a
  CLI mode, both keys present at once, and careful crash-midway semantics.
  **(b) dual-key decrypt fallback** — accept current + previous key env vars; wrap
  new uploads under current; on unwrap failure (`fileCipherDecrypt`,
  `Encryption.go:262-264` — AES-GCM authentication tells you the wrong key was used)
  retry with previous; retire the previous key once all pre-rotation files have aged
  out. **Recommendation: (b).** With Q1's 30-day retention every file wrapped under
  the old key is gone within 30 days, so (b) fully converges in one retention window
  with ~20 lines of fallback logic and no migration tool, no crash-midway states,
  and no double-key-in-flight tooling. Honesty note that applies to both: after a
  genuine master-key *compromise* the attacker already unwrapped the per-file keys,
  so neither (a) nor (b) re-secures existing ciphertext — the correct compromise
  response is accelerated expiry/deletion, and W12 documents that. (a) remains the
  escalation if a rotation must ever complete faster than the retention window.
- *Effort:* L (raised from M per Codex: the env-key source, the dual-key fallback,
  the startup canary, and the key-loss drill materials are each small but together
  are not an M) — a wrong key at startup must be detected loudly (`IsCorrectKey`
  exists per file, `Encryption.go:184-192`, but there is no global startup check;
  add a canary check against one stored file or a stored checksum, reusing the
  `PasswordChecksum` machinery at `Encryption.go:108-119`). *Risk:* medium.
- *Deps:* none. *Upstreamable:* yes — "key from env var" and dual-key fallback are
  provider-agnostic (separate commit from any Azure-specific docs, per Q7).
- *Gate hook:* W20 runs the wrong-key and lost-key drills against this
  implementation before go-live; key recovery = the Key Vault secret plus its
  documented backup/escrow, decided and drilled there.
- *Build vs. buy/borrow:* the recommended path needs **zero new dependencies** — App
  Service **Key Vault references** resolve the secret into the env var before the
  container starts, so Azure integration is bought entirely from the platform. If a
  direct in-process fetch is ever needed (e.g. rotation without restart), use the
  official `Azure/azure-sdk-for-go` `azsecrets` module with managed identity — never
  hand-written REST. Rejected: bundling `azsecrets` now (adds an Azure dependency to
  every build for a job the platform already does, and would kill upstreamability).
- *Acceptance:* container started with the env var and a `config.json` containing no
  cipher serves previously encrypted files; started with a wrong key it refuses to
  start (or clearly reports) rather than serving garbage; started with the var absent
  it fails fast. Unit tests for `Init` precedence.

**W11 — Stop advertising `Accept-Ranges: bytes` on server-decrypted downloads [Level-2-specific — the affected path only runs when the server decrypts]**
- *Why:* `Headers.write` sets `Accept-Ranges: bytes` for every encrypted file
  (`Headers.go:31-33`), but the server-decrypt path streams from offset 0 via
  `DecryptReader` and ignores `Range` (`FileServing.go:664-672`) — only the
  `http.ServeContent` branch honours ranges. Download managers and browser resume can
  request a range, get a 200 full body, and mis-assemble a corrupt file.
- *Design:* only set the header on paths that honour ranges.
- *Effort:* S. *Risk:* low. *Deps:* none. *Upstreamable:* yes.
- *Build vs. buy/borrow:* stdlib `net/http` semantics only; nothing to buy.
- *Acceptance:* `curl -H "Range: bytes=0-99"` on an encrypted local file gets a
  response without `Accept-Ranges`/`206` inconsistency; unencrypted files still support
  ranges.

### Phase 4 — Pre-go-live operational gate

**W20 — Pre-go-live operational gate: drills + restore-tested DR [decision-independent]**
- *Why:* Codex's top-ranked gap, accepted: going live for confidential data
  without a tested restore and key drill risks either silent data loss or —
  worse for this product — **resurrection of expired/deleted files from
  backups**, which breaks the core "nothing lingers" promise.
- *Gate checklist (each drilled in the W8 staging environment, results recorded;
  go-live blocks on 1, 2, 4 and 6):*
  1. **Coordinated restore:** Postgres PITR + data-share snapshot + config + Key
     Vault secrets restored together to a consistent point; RPO/RTO stated —
     recommend RPO 24 h / RTO 4 h (a temporary exchange tolerates data loss by
     design; resurrection is the real hazard).
  2. **Resurrection test:** after restoring an older snapshot, expired and
     deleted files must NOT become servable — verify `GetFile`'s expiry check
     (`FileServing.go:576-598, 957-960`) plus startup `CleanUp`
     (`cmd/gokapi/Main.go:69`) purge them, and test it, don't assume it.
  3. **Key drills** (server-side encryption path, per G1): wrong key at startup →
     the W6 canary refuses loudly; lost key → documented recovery from Key Vault
     backup/soft-delete; rotation → W6 dual-key fallback exercised.
  4. **Storage exhaustion:** `MinFreeSpaceMB` refusal behaviour
     (`Environment.go:73-74`) confirmed; W8 disk alert fires first.
  5. **Restart/redeploy** under an in-flight chunked upload and an in-flight
     download; document observed behaviour.
  6. **Cross-user authorization spot-checks:** permission matrix exercised
     (`UserPermEditOtherUploads` at `Api.go:95-98`, duplicate/list permissions at
     `Api.go:718-721`), guest endpoints probed unauthenticated, W4 hotlink purge
     re-verified in staging.
  7. **Incident tabletop** (procedures may be draft while W12 is deferred;
     minimum: who is called, bulk link revocation via
     `DeleteFiles`/`FileServing.go:1008-1017`, key rotation steps, break-glass).
  8. **Two-process double-download check** — informative while single-instance
     (Q4); becomes blocking before any scale-out (W2/W8 checklist).
- *Effort:* L (mostly operational). *Risk:* none to code. *Deps:* W6, W8.
  *Upstreamable:* no (runbook).
- *Build vs. buy/borrow:* Azure-native backup/restore mechanisms; no code.
- *Acceptance:* a written gate record with pass/fail per line, signed by the
  service owner; failures on lines 1, 2, 4 or 6 block go-live.

### Phase 5 — Deferred compliance apparatus & hygiene (post-go-live)

Deferred purely because formal PIPEDA/HIPAA work is deferred (user scope
decision), except W13/W14/W19 which are ordinary hygiene. This list IS the
written gap register for the future compliance project: W15 (signing/immutable
sink), W16 (verifier), W12 (policies/procedures/notices), plus the Q8(b) lock
decision. Nothing here blocks go-live; W7's capture design is what makes that
safe.

**W15 — Signed, verifiable audit trail over the W7 chain (pluggable sinks) [decision-independent; DEFERRED post-go-live by the user's scope decision]**
- *Why:* the user requirement "signed and verified" stands, but formal compliance
  work is deferred. Because W7 already writes the canonical, chained, durably
  committed event stream from day one, W15 can be layered on later **without
  migration**: it adds (1) signed checkpoints, (2) the immutable/remote sink and
  its async shipper, (3) the tee. What deferral costs is stated in W7: events
  written before the first signed checkpoint are protected only from tampering
  that occurs *after* that checkpoint. Recommendation stands: chain from first
  deployment, sign at W15.
- *Why not a managed service alone (adjudicating Codex's overengineering charge):*
  Azure Log Analytics is practically append-only (no user modify API; purge is a
  privileged, audited operation) and locked immutable blobs give platform-enforced
  WORM — but neither yields a **cryptographically signed stream a third party can
  verify offline**, which is the user's stated requirement, nor works for the
  no-cloud upstream default. That missing property — offline cryptographic
  verifiability — defines the minimum bespoke component: checkpoint signing over
  the W7 chain plus a verifier (W16). Everything else is bought: WORM from Azure
  storage, alerting from Azure Monitor, key custody from Key Vault. Codex's charge
  was fair against the original five-sink/two-scheme scope; that scope is cut.
- *Standards grounding (unchanged from the reviewed design):* NIST SP 800-92 for
  log-management vocabulary and log-failure handling; RFC 8032 Ed25519 via stdlib
  `crypto/ed25519` for the upstream/local default signer; RFC 6962 assessed —
  linear chain + signed checkpoints is the list-shaped degenerate case, sufficient
  at ≤ tens of thousands of entries, with `github.com/transparency-dev/merkle` as
  the recorded upgrade path if inclusion proofs are ever demanded; RFC 3161
  assessed and deferred (Q8(d) below); journald-FSS forward security assessed —
  see the honesty note on Key Vault below.
- *Scope (v1, reduced):*
  - **Signer:** interface with two implementations, in **separate commits per Q7**:
    (a) local Ed25519 (stdlib) — the upstream-extractable default; (b) **Azure Key
    Vault `Sign` (Q8(c), DECIDED)** via the official `azkeys` SDK + managed
    identity, ES256/P-256 (Key Vault standard tier offers no Ed25519 — verifier
    handles both, all stdlib). Checkpoint cadence: every N events / T minutes /
    shutdown — never per-request.
  - **What Key Vault does and does not buy (per Codex's correction, stated so the
    operator can repeat it to an auditor):** it prevents key *exfiltration* (no
    export; DB/backup/filesystem compromise never yields the key; no key sprawl;
    an attacker evicted from the container cannot forge checkpoints afterwards,
    and every Sign call lands in Key Vault's own audit log). It does **not** stop
    a live attacker who controls the running app from invoking Sign on forged
    content — signing *authority* travels with the managed identity. Key Vault
    alone is therefore not forward security. What closes that gap: (i) the WORM
    sink, which makes already-committed history immutable regardless of signing
    ability — **this is the proportionate control here and is in scope**; (ii)
    moving checkpoint signing to a separate identity (e.g. a scheduled job that
    countersigns the WORM blob) — deferred, disproportionate for now; (iii)
    off-box checkpoint publication — see Q8(d).
  - **Sinks:** exactly two at launch — the W7 local chained file (authoritative,
    fail-closed) and an **Azure append blob under a time-based immutability policy
    with protected append writes** via the official `azblob` SDK, isolated in a
    build-tagged subpackage (separate commit from the sink interface, per Q7).
    Cut from v1: S3 Object Lock backend, syslog/OTLP sink, generic tee fan-out
    beyond these two. The `AuditSink` interface stays (that is the pluggability
    requirement), the extra backends do not.
  - **Shipping (Q8(a), DECIDED — fail closed on durable LOCAL write, ship async):**
    the hot path never waits on Azure. W7 already guarantees: append + fsync to
    the local chained file **before** the response body is served; local write
    failure ⇒ refuse (503). W15 adds the out-of-band shipper: tail the local
    file, append batches to the immutable blob, resume from a persisted
    last-shipped-seq cursor (at-least-once with seq-dedup on verify). The local
    file **is** the spool; its bound is the config-volume free space. On spool
    exhaustion the local append fails and the service stops accepting auditable
    operations — this is Common Criteria **FAU_STG.4 "prevent auditable events"**
    behaviour, chosen deliberately per the fail-closed decision and consistent
    with NIST SP 800-92 log-failure handling, rather than an invented policy.
    Escalation: Azure Monitor warning at ship-lag > 15 min, critical at > 4 h,
    plus a disk-headroom alert well before exhaustion (W8 alerts). **Break-glass:**
    if the audit subsystem itself is broken and service must be restored, a
    deliberate `GOKAPI_AUDIT_BREAK_GLASS=<ticket-ref>` app setting allows serving
    with stderr-only audit mirroring; setting it is itself recorded (the app
    setting change appears in the Azure activity log with the operator's
    identity, and the first entry after recovery records the break-glass window
    and ticket), so the escape hatch is auditable.
  - *Q8(b) — recommendation (open, needs sign-off):* immutability policy of
    **365 days, LOCKED**, total audit retention **2 years** then deletion.
    Reasoning: the log now contains IPs (Q2) and filenames — a PI repository —
    so PIPEDA minimisation argues against six-year hot retention; a one-year
    locked window covers incident-investigation value while bounding the
    irreversibility of LOCK (locking a short window is low-regret; locking six
    years is not); the HIPAA six-year expectation attaches to *documentation and
    policies* (kept six years in W12) rather than to raw access-log lines, and if
    the later compliance project disagrees it can extend retention **forward**
    (never possible backward anyway). DSAR conflict is handled by documented
    carve-out: within the immutable window, deletion requests against log IPs are
    declined on security-retention grounds, disclosed in the W7 privacy notice
    and recorded in W12.
  - *Q8(d) — recommendation:* **defer** external witness and RFC 3161. Triggers
    that change the answer: an auditor or client contract demands third-party
    time attestation, or the threat model must cover collusion between the app
    operator and the storage/Key Vault administrator. Cheap interim adopted at
    the W20 gate: quarterly manual export of the latest checkpoint hash into the
    compliance ticket — a near-zero-cost witness.
- *Honest guarantees:* unchanged in kind — detection everywhere (chain + seq +
  checkpoints), prevention only on the WORM sink, no protection against events
  suppressed/forged *before* first write by a compromised app (true of every
  logging system), third-party verifiability offline via W16 but no public
  transparency ecosystem.
- *Touches:* `internal/logging/audit/` (signer, checkpoint, sink interface,
  shipper), `audit/azureblob` (build-tagged), `Environment.go`, W8 alerts.
- *Effort:* L for this reduced scope (Codex's XL applied to the original
  five-sink/two-scheme platform, which is cut). *Risk:* medium. *Deps:* W7 (chain
  format), W8 (Azure infra), Q8(b) sign-off.
- *Upstreamable:* sink interface + local Ed25519 signer + verifier, yes (separate
  commits); Azure backend stays fork-side behind a build tag.
- *Build vs. buy/borrow:* alternatives assessed and rejected with reasons —
  `transparency-dev/merkle` (proof machinery unneeded at this scale; recorded
  upgrade path), Trillian and immudb (separate stateful services a 4-user
  deployment cannot justify operating), Rekor (public-transparency posture wrong
  for PHI-adjacent data), Azure WORM alone and Log Analytics alone (no offline
  cryptographic verifiability — fails the standing "signed and verified"
  requirement; see the managed-service paragraph above and the §4 rows). The
  bespoke core is deliberately small: checkpoint signing + shipper over the W7
  chain, stdlib crypto only; WORM enforcement, alerting and key custody are all
  bought from Azure.
- *Acceptance:* checkpoint appears after N events and on shutdown; blob
  modify/delete attempts within retention are refused by Azure (staging with
  unlocked policy; production locked per Q8(b) once signed off); kill -9 between
  fsync and response leaves a verifiable chain with the event present; ship-lag
  alert fires when the shipper is paused; break-glass drill leaves the documented
  trace; serving is refused (503) when the local audit volume is full.

**W16 — Audit verifier (CLI) [decision-independent; deferred with W15]**
- *Why:* a tamper-evident log nobody can check is theatre. There must be a tool
  that walks the chain, checks signatures, and reports the first divergence.
- *Design:* CLI subcommand on the existing flag parser (`cmd/gokapi/Main.go:50`
  `flagparser.ParseFlags`): `gokapi --audit-verify [--audit-sink <spec>]
  [--from-seq N] [--pubkey <file|kv-uri>]`. Reads either backend through the W15
  `AuditSink` read interface, recomputes the chain, verifies every checkpoint
  signature (Ed25519 or ES256), checks `seq` monotonicity and cross-segment
  continuity, and — for the shipped blob — cross-checks it against the local
  stream by seq. Note: **pure chain verification works against W7 output even
  before W15 ships** (no signatures yet); shipping a minimal `--audit-verify
  --chain-only` early alongside W7 is cheap and recommended. Output: `OK` summary
  or `TAMPER at seq=…` with position and failed check. Exit codes: 0 verified,
  1 tampering/gap, 2 operational error. Run on a schedule so verification is an
  operational control, not a ceremony.
- *Touches:* `internal/logging/audit` (verify walk), `cmd/gokapi/Main.go` +
  `flagparser`.
- *Effort:* M. *Risk:* low. *Deps:* W7 (chain-only mode), W15 (full mode).
- *Upstreamable:* yes, ships with the W15 sink/signer commits.
- *Build vs. buy/borrow:* stdlib crypto + the W15 sink interface; the framing is
  ours by construction, the primitives are standard.
- *Acceptance (tamper drill, automated):* seed 1,000 events on both backends, then
  per backend: (a) mutate a middle entry, (b) delete a middle entry, (c) truncate
  the tail past the last checkpoint, (d) re-sign with a wrong key — verifier exits
  1 with the exact first divergent seq; clean stream exits 0; unreachable sink
  exits 2; chain-only mode catches (a)-(b) on pre-W15 W7 output.

**W12 — Retention/disposal and breach-notification documentation (PIPEDA) [decision-independent; deferred with the compliance project]**
- *Why:* Stated requirement; documentation, not code.
- *Content:* data map (what PHI/PII may transit; where it rests: Azure Files blob +
  Postgres metadata incl. filenames, sizes, `PasswordHash`, optional IPs in logs);
  retention: `GOKAPI_MAX_EXPIRY` clamp + hourly `CleanUp`
  (`FileServing.go:813-852`) + verified-on-delete behaviour (`DeleteFile` revokes
  metadata synchronously — sets `ExpireAt=0`, saves, `GetFile` then refuses to serve
  (`FileServing.go:987-1002`, `:576-598`) — then `go CleanUp(false)` removes the blob);
  disposal caveat: Azure Files deletion is logical (no shredding) — rely on Azure
  storage-side encryption + key custody for defensible disposal; breach-notification
  runbook (PIPEDA "real risk of significant harm" test, notify OPC + individuals,
  record-keeping; key-compromise scenario = rotate W6 secret, which orphans ciphertext);
  AGPL §13 compliance: footer/about link to the public fork repo offering source to
  network users.
- *Effort:* M. *Risk:* none. *Deps:* W6, W7, W8 decisions; W15/W16 (document the
  audit-integrity control, the NIST SP 800-92 mapping, and the verifier cadence).
- *Upstreamable:* no.
- *Build vs. buy/borrow:* documentation; borrow structure from OPC's PIPEDA breach
  guidance and NIST SP 800-92 headings rather than inventing a format.
- *Acceptance:* documents reviewed and signed off by the privacy owner; the AGPL source
  link is visible on public pages (can ride the W10 `public.js`).

**W13 — Skip empty E2E rows in DB migration (F9) [decision-independent]**
- *Why:* Hygiene; keeps "who has E2E configured" queries meaningful.
- *Touches:* `internal/configuration/database/Database.go:83-88` — only call
  `SaveEnd2EndInfo` when the fetched `models.E2EInfoEncrypted` is non-empty.
- *Effort:* S. *Risk:* low. *Deps:* none. *Upstreamable:* yes.
- *Build vs. buy/borrow:* one-line guard; nothing applicable.
- *Acceptance:* migration test asserts no `E2EConfig` row for a user who had none.

**W14 — WASM downloader buffer fix (upstream courtesy) [decision-independent — not hot-path relevant since G1 chose server-side encryption over E2E]**
- *Why:* `cmd/wasmdownloader/Main.go:93` allocates a fresh 1 MiB buffer per `Read`
  while `sio.DecReader.Read` returns ≤ one 16 KiB package per call → ~97 % waste.
  Unreachable in our deployment — this path only runs for S3-stored or E2E files,
  and neither applies here — but a two-line fix (hoist the buffer out of the
  loop) that keeps the fork close to upstream and helps other users.
- *Effort:* S. *Risk:* low (WASM build via `go generate`, `build/go-generate/buildWasm.go`).
- *Deps:* none. *Upstreamable:* yes — primary motivation.
- *Build vs. buy/borrow:* two-line hoist; nothing applicable.
- *Acceptance:* WASM module still round-trips an E2E file in an E2E-level test env;
  buffer allocated once per stream.

---

**W19 — Supply chain & upstream-patch tracking [decision-independent]**
- *Why (Codex finding, VERIFIED):* CI only generates and tests
  (`.github/workflows/test-code.yml:17-20`); there is no vulnerability scanning,
  SBOM, secret scanning, digest pinning, or defined upstream-security-patch
  cadence — while the fork is now the AGPL-distributed artifact serving
  confidential data.
- *Design:* add `govulncheck` and secret-scanning jobs to CI; dependabot/renovate
  for gomod, actions and base images; pin container base images by digest;
  generate an SBOM artifact per release; a monthly upstream-rebase check with a
  written patch SLA (upstream security fix → deployed within N days). Q7's
  single-purpose-commit rule is what makes the rebase cheap — record that link.
- *Effort:* M. *Risk:* low. *Deps:* none. *Upstreamable:* partially (upstream owns
  its own CI); mostly fork-operational.
- *Build vs. buy/borrow:* entirely borrowed tooling (govulncheck, dependabot,
  syft/`go mod` SBOM); zero bespoke code.
- *Acceptance:* CI fails on an intentionally-pinned known-vulnerable module;
  SBOM artifact attached to a build; one upstream-rebase dry run executed and
  documented.

## 4. CANCELLED / NOT-DOING / ACCEPTED-RISK (explicit)

| Item | Status | Reason |
|---|---|---|
| X25519 / NaCl sealed-box inbound encryption (branch purpose) | **RESOLVED, not built** | The G1 decision (2026-08-31) chose server-side encryption instead; inbound at-rest protection comes from server-side encryption + W6. Grep confirms none of the X25519/NaCl design was ever implemented here. Naming note: the later commit `b3a555c` also uses the term "sealed-box", but for the token-based share-access feature — that is unrelated to this X25519 inbound-crypto design; do not conflate the two. |
| Level 3 E2E hardening (guest-E2E UX, key recovery UX, Firefox truncation) | **NOT-DOING — G1 decided against E2E** | Same condition as above; W3 meanwhile blocks E2E assertions at non-E2E levels. |
| **Malware scanning / AV (Q6)** | **CANCELLED — user decision, recorded as ACCEPTED RISK** | User's rationale: "some documents cannot be uploaded outside." **Factual note the user should see before this becomes permanent:** ClamAV (clamd) would run *inside* the deployment — it downloads signature definitions from a CDN but never transmits file content to any third party — so if the concern is third-party transmission, it may not apply to a local scanner. The decision stands unless the user revisits it. **Compensating controls in place:** 30-day hard expiry (Q1 + W17 closing the edit hole), download caps (W2), uploads are never executed server-side and inline views get `Content-Security-Policy: sandbox` (`Headers.go:19-21`), hotlinks disabled entirely (W4), guest upload count/size caps (`Environment.go:63-70`), OIDC-gated admin (W9), and full access audit (W7). Codex ranked missing AV #3 — this row is the documented decision, not an oversight. |
| streamSaver `{size: N}` download-progress fix | **NOT-DOING — G1 chose server-side encryption over E2E** | WASM path not rendered under server-side encryption + local storage (`Webserver.go:582`, `html_download.tmpl:37,59`). Would return to scope only if E2E were adopted later, which is not planned. |
| ChaCha20-Poly1305 stream-cipher switch | **NOT-DOING** | Server-side decrypt runs native Go with hardware AES-GCM; a format break orphans ciphertext and diverges from upstream `sio-go` usage (`Encryption.go:245-256`) for no user-visible gain. |
| Trillian / Sigstore Rekor / immudb as audit backbone | **NOT-DOING** | W15 build-vs-buy table: separate stateful services (or a public-transparency posture wrong for PHI-adjacent data) that a 4-user deployment cannot justify; `transparency-dev/merkle` recorded as upgrade path. |
| Azure WORM as the *sole* audit mechanism | **NOT-DOING** | Fails the user's "signed and verified" requirement (no offline cryptographic verifiability), leaves the no-cloud default with nothing, kills upstreamability. It is one W15 backend, adding prevention atop detection. |
| RFC 3161 timestamping / external witness | **DEFERRED — recommendation in W15/Q8(d)** | Disproportionate now; monotonic seq + signed checkpoints + WORM ingestion timestamps bound backdating. Triggers to revisit: auditor/contract demand, or threat model covering operator+storage-admin collusion. Interim: quarterly checkpoint-hash export (W20). |
| Distributed / IP-based abuse controls beyond what exists | **PARTIAL — ACCEPTED RISK while single-instance (Q4)** | What exists (verified): guest file-count/size caps (`Environment.go:63-70`), UUID-reservation limiter for unlimited file requests (`Api.go:394-400`), download-password rate limiter (`Webserver.go:604`), disk floor (`MinFreeSpaceMB`). The limiter store is process-local (`ratelimiter/RateLimiter.go:38-44`) — irrelevant at one instance. Added now: W8 storage/request alerts. A distributed limiter is on the W8 scale-out checklist, not built speculatively. |
| Hashing bearer tokens at rest | **PROMOTED to W21** (was DEFERRED) | Q5 decided yes. Removed from this list. |
| yopass as a platform replacement | **NOT-DOING (considered and closed)** | File cap 512 KB default / 1 MB hard without licence vs MB-GB medical documents; expiry presets only 1h/1d/1w — incompatible with Q1's 30-day retention; OIDC, audit logging, secret requests, webhooks, read receipts, theming all licence-gated; and even the licensed audit log has no signing or tamper-evidence, so the standing "signed and verified" requirement cannot be bought there. Its Secret Requests design and several patterns — the fingerprint-in-fragment key-verification check and management-token-gated one-time retrieval — were recorded as prior art when G1 was decided, but were not built. |
| Read-only split deployment (yopass `--read-only` pattern) | **DEFERRED** | Assessed: the attack-surface win is smaller for Gokapi than for yopass because flow 2 (file-request inbound) requires a public WRITE path by definition — a retrieval-only public instance breaks the product. The residual win — an "admin-off" public instance with `/login`, `/admin` and the admin API disabled — is a plausible small upstreamable flag, but conflicts with Q4 (single instance) today. Recorded on the W8 scale-out checklist for re-evaluation. |
| Webhook payload hygiene (hashed id, HMAC-SHA256 + constant-time compare, backoff, stable delivery ID) | **RECORDED as precedent, no work item** | Share-link mail notifications now exist (`internal/mail/`: SMTP + Azure, resend, delivery receipts, audit); what remains absent is generic outbound webhooks. If a webhook mechanism is ever added, the yopass scheme is the template. |
| F7 residual upsert asymmetries (`Users.Name`, `ApiKeys.PublicId`) | **NOT-DOING now** | Low severity; Postgres refusal is safer than SQLite clobber; surfaces only on operator rename collisions. Revisit if hit. |
| S3Proxy / Azure Blob storage backend | **DEFERRED** | Local storage chosen. Warning stands: S3-style storage flips `RequiresClientDecryption()` true again (`FileList.go:159`) — re-verify the server-decrypt-path consequences (WASM download page re-enabled, hotlinks, dedup by content hash) before adopting. |
| Scale-out beyond one instance | **DEFERRED — Q4 decided "single instance for now"** | W8 records the full per-instance checklist (W2, downloadstatus, SSE, rate limiter, CleanUp timer, audit seq writer, ARR affinity) so a future scale-out is a checklist, not a rediscovery. |

## 5. Decision register (settled) and open questions

**Settled by the user — recorded, not re-litigated:**

1. **Q0 (G1), decided 2026-08-31: server-side encryption, no E2E; FullEncryptionStored
   or FullEncryptionInput; production runs Level 4 (sealed boot, passphrase unseal).**
2. **Q1 — Retention: `GOKAPI_MAX_EXPIRY=720h` (30 days).** Consequences folded in: 30 d
   (vs the earlier 7-d assumption) strengthens the case for W6's dual-key
   rotation (a full key generation now takes a month to age out) and lengthens
   the leaked-link exposure window — so W8 sets staff-facing *defaults* low
   (recommend 7-day expiry preset, small download counts); 30 is the ceiling,
   not the norm. Requires W17, or the cap is fiction on the edit path.
3. **Q2 — Downloader IP logging: YES**, implemented with PIPEDA controls in W7
   (purpose limitation, full-IP-vs-hash analysis with reasons, privacy notice,
   PI-repository handling, retention per Q8(b)).
4. **Q4 — Single App Service instance, for now.** W2 remains a correctness fix
   but not a launch gate; scaling without it silently breaks one-time links;
   W8 carries the scale-out checklist.
5. **Q5 — Hash session tokens & API keys at rest: YES** → W21, behind a
   replaceable credential seam per the user's plugin note.
6. **Q6 — No malware scanning** → accepted risk, §4 row (with the local-ClamAV
   factual note the user should read once).
7. **Q7 — Upstreaming: build first, extract later.** Commit-hygiene rule in §2:
   one concern per commit, upstreamable vs company-specific split (W15, W21
   called out), no history rewriting. AGPL §13 offer independent of upstreaming
   (W12).
8. **Q8(a) — Audit sink failure: FAIL CLOSED**, best-practice shape: durable
   fsync'd LOCAL commit before serving (W7), async shipping with spool, alerts,
   FAU_STG.4 "prevent auditable events" on exhaustion, auditable break-glass
   (W15).
9. **Q8(c) — Audit signing key in Azure Key Vault**, with the honest guarantee
   statement in W15 (prevents exfiltration/offline forgery; does NOT stop a live
   compromised app from signing; WORM sink is the proportionate control that
   protects committed history).

**Open — needing a human decision:**

- **Q3 — Key rotation approach (only if Level 2):** recommendation recorded in
  W6 — **(b) dual-key decrypt fallback** (current + previous key; old files age
  out inside the 30-day window) over (a) re-wrap migration tooling; (a) remains
  the emergency-rotation escalation. Needs user confirmation. Honest note: after
  a real master-key compromise neither re-secures existing ciphertext —
  accelerated expiry is the response.
- **Q8(b) — Audit retention & lock:** recommendation in W15 — 365-day LOCKED
  immutability window, 2-year total retention, DSAR carve-out documented;
  needs privacy-owner sign-off (deferred with the compliance project, but the
  Azure policy choice arises when W15 ships).
- **Q8(d) — External witness / RFC 3161:** recommend DEFER; triggers and the
  cheap quarterly-checkpoint-export interim are in W15.

## 5a. Compliance as configurable profiles, not built-in behaviour

**User direction, recorded 2026-08-27.** Audit and compliance behaviour must **not** be
mandatory or hardcoded. It should be expressed as selectable features or profiles, so an
operator turns on the specific controls they need — for example log retention, file
retention, which events are captured, and how logs are retrieved — rather than the
product imposing one regime on everyone.

This is a design correction to work already delivered. W7 currently hardwires its
behaviour: the event set, fail-closed writing, IP capture and the chained format are all
unconditional. That was reasonable for getting capture in place, but it is the wrong
long-term shape.

**Why this direction is right, beyond the user's preference.** It is also what makes the
work upstreamable. Upstream Gokapi would not accept a general-purpose file-sharing tool
that forces healthcare-grade audit behaviour on every install, but would plausibly accept
an optional profile mechanism with a light default. That directly serves the Q7 decision
to keep each concern separately extractable.

**Shape to aim for** (not yet designed in detail; do this before W15):
- A profile selector (`none` / `basic` / a named regime / `custom`) with per-setting
  overrides, following the existing env-var and setup-wizard conventions.
- Settings that should be individually controllable: which event categories are captured;
  audit log retention; file retention (`GOKAPI_MAX_EXPIRY` already exists and should
  fold into this); whether audit writes are fail-closed or best-effort; whether client IPs
  are recorded (`SaveIp` exists); how logs are retrieved or exported.
- The **default must stay light** — a plain self-hosted install should not pay for
  controls it did not ask for, and must not be able to take itself down through a
  fail-closed audit path it never opted into.

**Consequence for the W7 availability note above:** fail-closed serving becomes a profile
setting rather than an unconditional behaviour, which also removes the objection that a
corrupt audit file can stop an install that never wanted audit guarantees in the first
place.

**Affects:** W7 (retrofit behind the profile), W15/W16 (design against it from the
start), W12 (the profile is what the documentation describes), and the deferred
compliance work generally.

---

## 5b. Reference projects evaluated

Three comparable products were read in depth. None replaces Gokapi as the base — the
combination this product needs (large files, both directions, accounts and an audit
trail) does not exist off the shelf, which is why the fork exists. What each one is
useful for is recorded here so the evaluation is not repeated.

### yopass (jhaals/yopass) — Apache-2.0, ~3.1k stars, very actively maintained

**Why it cannot be the base.** File cap 512 KB default and 1 MB hard without a licence;
expiry presets are only 1h/1d/1w, so the decided 30-day retention (Q1) is impossible;
OIDC, audit logging, secret requests, webhooks and theming are all licence-gated; and
critically, even the licensed audit log has **no tamper-evidence or signing**, so the
standing "signed and verified" requirement cannot be bought there. It is a secrets tool,
not a file-exchange platform. Note the licence-gated features' source **is** in the
Apache-2.0 repository behind a runtime key check; if its features ever fit, the correct
response is to buy a licence, not to strip the gate.

**Why it is worth keeping as a design reference.** Its "Secret Requests" feature is a
shipped, working implementation of the sealed-box design that was cancelled here:
the requester's browser generates an ECC key pair, the public key is registered
server-side, the private key stays in `localStorage`, and the responder's browser
fetches the public key, **verifies it against a fingerprint carried in the URL fragment**
(so a server substituting its own key is detectable), then encrypts with OpenPGP. G1
decided against a hybrid, so this was not built, but it remains the design to study if
a hybrid is ever revisited — including the fingerprint check, which is a refinement
this plan had not proposed.

**The countervailing signal, which matters more than the reference value.** yopass caps
Secret Request file responses at 512 KB and stores them in the database backend only,
while its *ordinary* uploads stream via `file.stream()` and support disk/S3. Reading the
source explains why: `encryptFileWithPublicKey` does `new Uint8Array(await
file.arrayBuffer())` — the whole file in memory — whereas the symmetric upload path
streams. **The asymmetric path does not stream, and streaming is exactly the part we
would need.** A hybrid design here must seal a random file key and stream the body under
it; yopass does not demonstrate that, so the reference stops short of the hard part.

Also worth borrowing independently of the G1 decision: the audit field set (adopted into W7); putting the
filename **inside** the encrypted packet rather than in the URL fragment; webhook payload
hygiene (a SHA-256 fingerprint of the id rather than the id, HMAC-signed body,
exponential-backoff retries with a stable delivery id); and the read-only split
deployment, where an internet-facing instance has creation endpoints disabled entirely
and shares a database with an internal instance that can create.

### PrivCloud_Sharing (Simthem/PrivCloud_Sharing) — BSD-2 fork of Pingvin Share

**Assessment: do not adopt.** 2 stars, 1 fork, created February 2026, effectively one
author, with an unusually large security-critical surface built very fast — team
workspaces, folders, access logs, PDF signing at QES level, WebDAV import, four mail
integrations, and "post-quantum-ready" ML-KEM. The README claims no security audit and
carries no warning that the cryptography is unreviewed, which is a weaker posture than
upstream Gokapi, whose own docs at least state plainly that its encryption has not been
independently audited. Attribution is handled correctly (BSD-2 retaining Elias
Schneider's copyright plus a modification notice).

**The specific technical objection.** Its anonymous reverse shares use a **symmetric
per-reverse-share key carried in the link fragment**: "senders encrypt files with the key
from the link fragment." Anyone holding that link can therefore **decrypt** everything
uploaded through it, not merely encrypt to it. For this product's inbound flow — several
different clients uploading to us — that means one client could read another's upload,
and a forwarded link exposes everything already sent. Compare yopass's asymmetric design,
where the sender holds only a public key and cannot decrypt even their own submission.
Both are described as end-to-end encrypted reverse shares; the confidentiality guarantees
are materially different. Its ML-KEM support is metadata/key storage only, not in use for
user data.

**What it does establish — now moot.** At the time of this review the Pingvin lineage's
folder and team models looked like a gap against Gokapi, and pingvin-share-x (~370
stars, actively maintained, the successor the archived upstream itself points to) was
recorded as the candidate base to evaluate if multi-file grouping became a hard
requirement. Folders and bundles have since shipped on this fork directly, so a base
change for that reason is moot.

