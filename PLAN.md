# PLAN — Gokapi fork: Level 2 server-managed encryption for a temporary file exchange

Branch: `feat/sealed-box-inbound` (name now historical — sealed-box work is cancelled, see §4).
Base: upstream `618ecf1`, plus fork commits `35eccd1` (Postgres provider), `b2b2f2f`
(Postgres hardening), `fcb5ed3` (`GOKAPI_MAX_EXPIRY_DAYS`).

Product: self-hosted TEMPORARY file exchange (send-to-client, client-upload-to-us,
internal exchange) for a Canadian healthcare-adjacent company (PIPEDA, HIPAA-adjacent).
Google Drive remains storage of record; nothing may linger here.

---

## 1. Decision record — Level 2 "Full encryption" as a PROVISIONAL working assumption

**Status: PROVISIONAL, not final.** The user has said "we will discuss about e2e
and server key later." The plan therefore treats "Level 2 — Full" server-managed
encryption (`docs/setup.rst:314`), LOCAL storage, metadata in PostgreSQL as the
**working assumption** for analysis and for the Level-2-specific items (W6, W11),
while every other work item is partitioned as decision-independent and sequenced
first (§2). The decision itself is taken at **GATE G1** (§2), which is a point of
no return: it must be made **before the first real client file is uploaded**,
because changing the encryption level afterwards deletes all encrypted storage
(`Setup.go:640-651`, `docs/setup.rst:333`). The §1.5 decision brief is what the
user decides from. The X25519 sealed-box inbound work remains stopped, but is
**shelved pending G1** rather than permanently cancelled (§4).

**Whatever G1 decides, this is a risk-appetite trade — not a compliance
requirement in either direction.** Neither HIPAA nor PIPEDA *requires* E2E, but
nothing in either prefers server-readable data. What Level 2 buys is operational:
inbound malware scanning becomes *possible* (the company has since declined it — Q6
accepted risk, §4), key recovery and content attestation exist, downloads work
natively on every device, and the encryption path that carries guest uploads is
server-controlled instead of absent (§1.1, F1). What it costs — the
**server-compromise blast radius** — is stated plainly: an attacker who controls
the running application (or a malicious administrator, or a debugger attached to the
process) can read **every active file**, because the master key is loaded into
process memory at startup (`internal/encryption/Encryption.go:52-63, 128-147`) and
plaintext transits the process on every upload and download
(`FileServing.go:460-498, 664-672`), plus the pre-encryption temp/chunk window
(§1.3). Under Level 3 that blast radius would have been limited to guest-inbound
files (which land plaintext anyway, F1) and to whatever an attacker could serve
malicious JS for. The residual controls against this are: short retention (Q1/W17),
key custody outside the data volume (W6), audit trail (W7/W15/W16), and the
pre-go-live gate (W20). A **per-flow hybrid** (E2E for outbound/internal, a
server-decryptable or recipient-public-key path for inbound) was considered and
**deferred**: upstream has no recipient-key inbound path (the cancelled sealed-box
work was exactly that, unimplemented), running two crypto regimes doubles the
serving/test/UX matrix, and the highest-risk flow — anonymous guest inbound —
cannot be E2E'd at all without that unbuilt machinery. The full comparison,
including the hybrid, is in the §1.5 decision brief; the decision is taken at G1.

**Terminology mapping (important).** The wizard's user-facing "Level 2 — Full" maps to
internal constants `FullEncryptionStored = 3` or `FullEncryptionInput = 4`
(`internal/encryption/Encryption.go:31-35`), selected by the "enter password at startup"
toggle (`internal/configuration/setup/Setup.go:645-666`). Because App Service containers
must restart unattended, only the **Stored** variant (or the env-sourced key of W6) is
viable; `FullEncryptionInput` blocks on stdin at boot
(`internal/encryption/Encryption.go:80-84` `helper.ReadPassword()`).

### 1.1 Verified consequences of Level 2 + local storage (Phase 0 evidence, static)

All of the following were confirmed by reading the code. The headline assumption in the
decision **holds**:

- `RequiresClientDecryption()` is exactly
  `!f.IsLocalStorage() || f.Encryption.IsEndToEndEncrypted`
  (`internal/models/FileList.go:153-160`, guarded by `IsEncrypted`). With
  `FullEncryptionStored` + local storage both terms are false → **server decrypts**.
- **Serving path:** `storage.ServeFile` decrypts server-side via
  `encryption.DecryptReader(file.Encryption, fileHandler, w)`
  (`internal/storage/FileServing.go:664-672`); zip downloads likewise
  (`FileServing.go:707-760`).
- **WASM decrypt path is bypassed:** the download page only renders the WASM/streamSaver
  machinery inside `{{ if .ClientSideDecryption }}`
  (`internal/webserver/web/templates/html_download.tmpl:37-46, 59-124`), and
  `view.ClientSideDecryption` is set only when `file.RequiresClientDecryption()`
  (`internal/webserver/Webserver.go:582-588`). The non-encrypted branch is a plain
  `location.href = "./downloadFile?id=..."` (`html_download.tmpl:166-173`). The
  mobile-slowness problem and the streamSaver progress problem are therefore **moot**
  for this deployment.
- **Download progress:** `headers.Write` sets `Content-Type` and `Content-Length`
  whenever `!file.RequiresClientDecryption()`
  (`internal/webserver/headers/Headers.go:24-27`), so the browser gets a sized native
  download. `SizeBytes` is the plaintext size (`FileServing.go:299-307`) and
  `DecryptReader` emits exactly the plaintext, so the length is correct.
  *Caveat:* the docs table claims "Download Progress Indication: No" for Level 2
  (`docs/setup.rst:321`). The code says otherwise for local files; the docs row appears
  to describe the cloud-storage case (client-side decrypt). W1 verifies this
  empirically before anything is built on it.
- **Hotlinks become available again:** `IsAbleHotlink` only rejects on
  `RequiresClientDecryption()` / password / SVG (`FileServing.go:535-556`), so at
  Level 2 + local, image uploads DO get hotlinks — matching "Hotlink Support: Local
  files only" in `docs/setup.rst:319`. The company wants them OFF → W4.
- **Dedup works:** on-disk blobs are keyed by (salted) content hash; an upload whose
  hash matches an existing file reuses the existing blob and its encryption info
  (`FileServing.go:180-193 copyEncryptionInfo`, `FileServing.go:337-349
  getEncInfoFromExistingFile`).
- **Inbound guest uploads are now encrypted at rest** — this quietly resolves security
  finding F1. Encryption is decided purely by server config:
  `isEncryptionRequested()` returns `true` for `FullEncryption*` regardless of who
  uploads (`FileServing.go:500-514`), and the guest/file-request path hardcodes
  `isEnd2End=false` (`internal/webserver/fileupload/FileUpload.go:152-156`). Under
  Level 3 the same path stored guest files in plaintext (SECURITY-ANALYSIS.md F1); under
  Level 2 it cannot.
- **On-disk filename is salted at Level 2:** whenever encryption is requested, the
  content hash used as the on-disk name is salted with `Authentication.SaltFiles`
  (`FileServing.go:471, 493` for the non-chunked path; `FileServing.go:238-246`
  `getChunkFileHash` → `hashFile(file, isEncryptionRequested())` with the salt applied
  at `FileServing.go:446-456`). The "unsalted SHA1 permits content confirmation"
  concern applies only to levels where encryption is not requested — not to this
  deployment.
- **Fresh key per file is preserved:** `encryption.Encrypt` unconditionally calls
  `generateNewFileKey`, which draws a random 32-byte per-file key and a random 12-byte
  wrap nonce (`Encryption.go:152-161, 221-238`). Level 2 does not change this. The
  all-zero *stream* nonce (`Encryption.go:156,168,196,202,209,216`, `// Nonce is not
  used`) remains safe **only** because of this invariant → locked in by test W5.

### 1.2 What the Level 2 switch makes moot

- Sealed-box / X25519 asymmetric inbound encryption (the branch's original
  purpose) — shelved pending G1, not permanently cancelled (§4).
- All Level 3 E2E hardening (key distribution, `localStorage.e2ekey`, Firefox
  truncation caveat at `docs/setup.rst:337`).
- streamSaver `createWriteStream(filename, {size: N})` progress fix — WASM path unused.
- WASM downloader 1 MiB-per-iteration allocation (`cmd/wasmdownloader/Main.go:93`) —
  unreachable in this deployment (only reachable for S3-stored or E2E files); kept as an
  optional upstream courtesy patch (W14).
- ChaCha20-Poly1305 stream cipher switch — decryption now runs in native Go on servers
  with AES hardware acceleration; the ~6.8x software advantage evaporates and the format
  break (existing ciphertext, `sio.NewStream` AEAD swap, dedup hash compatibility) buys
  nothing. NOT-DOING (§4).

### 1.3 What Level 2 newly requires

- The master key `Encryption.Cipher` sits in `config.json`
  (`internal/models/Configuration.go:21, 29-35`), which on App Service lives on the same
  persistent share as the encrypted blobs — key and ciphertext on one volume. This is
  the single biggest defensibility gap of the switch → W6 (external secret source /
  Azure Key Vault via App Service Key Vault references).
- Server-side enforcement that clients cannot re-introduce the E2E marking: the `isE2E`
  flag is still client-asserted (`FileUpload.go:181`,
  `internal/webserver/api/routing.go:682`) → W3.
- Since the server can now read content, server-side controls (audit logging,
  hotlink policy, optional malware scanning) become possible → W4, W7. Scanning has
  since been declined by the user (Q6, accepted risk, §4).
- Because the server (not the client) is now the trust anchor, the audit trail is the
  compliance backbone: HIPAA §164.312(b) (audit controls) and §164.312(c)(1)
  (integrity) require being able to show access records were not altered or
  selectively deleted after the fact — including by someone with database, filesystem
  or admin access. Gokapi's current log is a plain mutable text file
  (`internal/logging/Logging.go:22`, `config/log.txt`) → W7 (coverage), W15
  (tamper-evident trail), W16 (verifier).
- Residual plaintext window: chunk files (`DataDir/chunk-<uuid>`,
  `internal/storage/chunking/Chunking.go:160`) and pre-encryption temp files
  (`os.CreateTemp(DataDir, "upload")`, `FileServing.go:477, 252`) hold plaintext until
  assembly + encryption completes, on the same volume. Accepted and documented (W8);
  no code change planned.

### 1.4 Reassessed findings under Level 2

- **F2 (client-asserted `isE2E`)** — severity drops from High to Medium but stays real.
  At Level 2 an authenticated client (web form `FileUpload.go:181` or API header
  `routing.go:682`, consumed at `internal/webserver/api/Api.go:487-495`) that asserts
  `isE2E=true` causes: metadata marked `IsEndToEndEncrypted: true`
  (`FileServing.go:316-319`), a random non-content hash (`"e2e-"+random`,
  `FileServing.go:238-241`, breaking dedup), **server-side encryption still applied**
  (config-driven, `FileServing.go:500-514`), but serving skips server decryption because
  `RequiresClientDecryption()` becomes true → the recipient downloads ciphertext
  garbage. So: no plaintext-at-rest risk anymore, but an integrity/labelling/DoS defect
  and a false "end-to-end encrypted" claim in the UI/API (`FileList.go:94-98`). Guests
  cannot set it (`FileUpload.go:152-156`). Fix is a cheap server-authoritative
  rejection → W3.
- **F1 (guest plaintext under E2E)** — resolved by the level switch itself (§1.1).
- **F3/F4/F5/F8** — already fixed in `b2b2f2f`: retry wrappers + connection recycling
  (`internal/configuration/database/provider/postgres/Postgres.go:17-96, 172-176`),
  TLS required for non-loopback Postgres (`Setup.go:951-963`), DSN redaction
  (`Database.go:388-398`, used at `Migration.go:26-27`; regression test
  `Database_test.go:498-501`), traffic clamp. Verified present.
  Residual F4 item — plaintext bearer tokens (session IDs, API keys) in the DB —
  is now W21 (Q5 decided yes).
- **F6 (download cap not atomic)** — confirmed OPEN. `ServeFile` guards the
  read-check-decrement with a process-local striped `sync.Mutex`
  (`FileServing.go:623-640`;
  `internal/webserver/api/mutex/apimutex/ApiMutex.go:8-37`), and the SQL decrement has
  no floor: `SET DownloadsRemaining = DownloadsRemaining - 1 WHERE Id = $1`
  (`postgres/metadata.go:169-177`; same shape in `sqlite/metadata.go:154`). Across two
  App Service instances a one-time link serves twice. → W2 (per Q4 single-instance,
  a correctness fix now and a hard precondition for any scale-out).
- **F7** — `SaveHotlink` conflict target fixed in `b2b2f2f`; the analogous
  secondary-unique asymmetries on `Users.Name`/`ApiKeys.PublicId` remain Low and are
  NOT-DOING for now (§4).
- **F9** — confirmed: `Database.go:87` writes an E2E row per user on migration → W13.

---

### 1.5 Decision brief — Level 2 vs Level 3 vs hybrid (for the G1 decision)

Self-contained, no advocacy. Neither HIPAA nor PIPEDA mandates E2E; nothing in
either prefers server-readable data. This is risk appetite, not compliance.

**Honest recompute after Q6:** the user has declined malware scanning. "Level 2
enables inbound AV" was one of the stronger arguments for Level 2; it is now
**largely moot** (only the *option* of adding scanning later remains). The
remaining live differentiators are below.

| | **Level 2 (server key)** | **Level 3 (E2E) as it exists today** | **Hybrid (E2E out/internal + separate inbound path)** |
|---|---|---|---|
| Server compromise / malicious admin | Reads **every active file** (master key in process memory, `Encryption.go:52-63`; plaintext transits on every request) | Reads nothing already stored for staff-uploaded flows; can serve malicious JS to capture future traffic | As L3 for out/internal; inbound depends on chosen inbound design |
| Guest inbound (flow 2 — clients upload to us) | Encrypted at rest, server-controlled (`FileServing.go:500-514`; verified) | **Stored in PLAINTEXT** — the F1 defect; guests have no E2E key (`SECURITY-ANALYSIS.md` F1) | Requires building the cancelled sealed-box path (encrypt-to-recipient-pubkey in guest browser) or a server-key inbound enclave |
| Key custody / recovery | W6 (Key Vault) required; key loss recoverable from vault backup | Key lives in each admin's browser `localStorage.e2ekey`; loss = permanent data loss; no server-side recovery | Both problems at once |
| Download UX | Native browser downloads, progress, mobile-fast (verified §1.1) | WASM decrypt path: slow on mobile, no native progress, Firefox truncation warning (`docs/setup.rst:337`), streamSaver service-worker dependency | E2E flows inherit L3 UX costs |
| Dedup / hotlinks | Work (hotlinks disabled by policy anyway, W4) | No dedup (`e2e-` random hashes, `FileServing.go:238-241`); no hotlinks (moot) | Mixed |
| Crypto assurance | Upstream server-side path reviewed here (fresh-key-per-file verified, W5); AES-GCM via `sio-go` | Upstream E2E is self-declared unaudited (`docs/setup.rst:308` warning) | **Revised:** re-implements a published design with a live reference implementation (yopass Secret Requests, incl. fingerprint-in-fragment key verification — see the yopass note below); design risk lowered, independent review still required |
| Malware scanning option | Possible later (currently declined, Q6) | Impossible | Impossible for E2E flows |
| Build cost from here | W6 (L) + W11 (S); everything else in this plan already fits | Zero new crypto code, but: accept guest-inbound plaintext OR build sealed-box; W6/W11 cancelled; W14 matters; re-verify the whole serving analysis | Sealed-box inbound **revised: XL, medium-high risk** — crypto *design* de-novo risk removed by the yopass reference, but large-file streaming is exactly what the reference does NOT demonstrate (512 KB cap — see below); recipient key mgmt, new serving path, double UX matrix and upstream divergence remain |
| Blast-radius containment | Short retention (Q1: 30d cap), audit trail, Key Vault custody, W20 drills | Structural for staff flows | Structural for staff flows only |

**New input for G1 — yopass "Secret Requests" (docs reviewed by the coordinator, all 14 pages):**
yopass ships a production implementation of essentially the cancelled sealed-box
design: (1) the requester's browser generates an ECC key pair, registers the
public key on the server, keeps the private key in browser localStorage; (2) the
responder's link carries the public key's **fingerprint in the URL fragment**
(`/#/r/<id>/<fingerprint>`), and the responder's browser verifies the fetched
public key against it before encrypting client-side with OpenPGP; (3) the
requester retrieves ciphertext with a management token and decrypts locally —
the server sees only ciphertext and a public key. Also: management-token-gated
retrieval/revocation/key rotation, one-time retrieval with atomic
compare-and-swap deletion, and a documented REST API.

*Implication (a) — hybrid risk re-rated (reflected in the table above):* this is
no longer "novel cryptography we invent" but re-implementation of a public
design with a live reference. The fingerprint-in-fragment step is a refinement
we had not proposed: the responder can detect a malicious/compromised server
substituting its own public key, because the fingerprint travels in the
requester's link (never sent to the server as part of the fragment). That
**partially** answers our recorded "browser-delivered crypto cannot defend
against a hostile host" objection — partially, because a hostile server can
still ship malicious JS that skips the check or exfiltrates plaintext at
*decrypt* time on the requester's side. Independent review of any
re-implementation remains a requirement.

*Implication (b) — countervailing warning, stated honestly:* yopass caps Secret
Request file responses at **512 KB** and stores them in the database backend
only, even though its ordinary uploads may use disk/S3 and exceed 1 MB with a
licence. That asymmetry is unlikely to be arbitrary — it suggests the
asymmetric-request flow has unresolved engineering constraints at size
(plausibly in-browser OpenPGP message construction, memory, or absence of
streaming in that path). Our payloads are medical documents in the MB-to-GB
range: **the streaming design we would need is precisely the part the reference
does NOT demonstrate.** If G1 leans hybrid, a size-realistic spike is a
mandatory pre-commitment step.

*Considered and closed — yopass as a platform replacement:* file cap 512 KB
default / 1 MB hard without licence (vs MB-GB documents); expiry presets only
1h/1d/1w, incompatible with the decided 30-day retention (Q1); OIDC, audit
logging, secret requests, webhooks, read receipts and theming all
licence-gated; and even the licensed audit log has **no tamper-evidence or
signing** — the standing "signed and verified" requirement cannot be bought
there. Recorded in §4.

*Patterns adopted or recorded regardless of G1:* audit record field set →
folded into W7 (identity, config-metadata and error-description fields);
reverse-proxy TLS (`X-Forwarded-Proto`) → folded into W18/W8 with the verified
Gokapi nuance; read-only split deployment → assessed, deferred (§4 row + W8
scale-out checklist); webhook payload hygiene (hashed `secret_id`, HMAC-SHA256
body signature with constant-time compare, backoff + stable delivery ID) →
recorded as the precedent for any future notification feature (Gokapi has
none today); metrics on a separate unauthenticated port secured at network
layer → noted in W8, not directly applicable on App Service's single exposed
port.

**Point of no return:** G1 must be decided before real data exists —
`Setup.go:640-651` deletes all encrypted files on any encryption reconfiguration;
there is no level-migration tooling.

**What is already sunk/committed either way:** Postgres provider + hardening,
expiry clamp, and every Phase 0-2 item — all decision-independent by design.

## 2. Phased work plan

Rules: after every item the full baseline must pass — `go generate ./...` then
`go test ./... -parallel 8 -count=1` with `--tags=test,noaws`, `--tags=test,awsmock`,
and `--tags=test,noaws,integration` (47/47, 47/47, 45/45; Postgres tests need
`GOKAPI_TEST_POSTGRES_URL` against container `gokapi-test-pg` on 127.0.0.1:15432; the
suite binds port 53842, so no dev server on it). Each phase ends with a product that
works end to end.

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

### Phase 0 — Verify the provisional Level 2 assumptions (throwaway environment)

**W1 — Runtime confirmation of the §1.1 claims [validates the provisional Level-2 assumption; feeds the §1.5 decision brief]**
- *Why:* Everything downstream (cancelled items, hotlink policy, progress claims)
  hangs on the static reading in §1.1; the docs table (`docs/setup.rst:319-321`)
  contradicts the code on progress indication, so an empirical check is mandatory.
- *Touches:* no product code. Local run: `--reconfigure` to Level "Full" with stored
  key, local storage, Postgres metadata.
- *Checks:* (a) uploaded file on disk at `data/<salted-hash>` is ciphertext (no
  plaintext magic bytes; name ≠ plain `sha1sum`); (b) `config.json` `Encryption.Level`
  is `3` and `Cipher` populated; (c) download of a ~500 MB file in Chrome/Firefox/mobile
  Safari shows native progress bar and correct final size; (d) download page HTML
  contains no `main.wasm` / `streamSaver` references; (e) image upload gets `/h/<id>`
  hotlink that serves without password (documents the pre-W4 behaviour); (f) two uploads
  of the same content share one blob (dedup); (g) file-request (guest) upload is
  ciphertext on disk; (h) `Accept-Ranges: bytes` is advertised on encrypted downloads
  (`Headers.go:32`) but a `Range` request returns the full body from offset 0 — record
  actual behaviour for W11.
- *Effort:* S. *Risk:* none (throwaway env). *Deps:* none. *Upstreamable:* n/a.
- *Build vs. buy/borrow:* n/a — verification only, no code.
- *Scope note (Codex sequencing point, adjudicated):* W1 deliberately verifies only
  the Level 2 encryption/serving semantics, because that is what the rest of the plan
  is conditioned on. The operational drills Codex wants (restart, wrong/lost key,
  restore, storage exhaustion, two-instance behaviour) require W6/W8 to exist first
  and are therefore the substance of the **W20 pre-go-live gate**, not of Phase 0.
- *Acceptance:* a short checklist of (a)-(h) with observed results appended to this file
  or the PR description; any deviation from §1.1 stops the plan for re-evaluation.

### Phase 1 — Decision-independent correctness & non-retrofittable capture

Everything here is valuable at any encryption level. W7 leads in priority: audit
events not captured now are unrecoverable later, whereas every other compliance
layer can be added afterwards.

**W7 — Audit event coverage + forward-compatible record format [decision-independent]**
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
- *Deps:* W1. *Upstreamable:* yes — upstream already fixed the single-process race
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

**W3 — Server-authoritative rejection of the `isE2E` upload flag (F2) [decision-independent]**
- *Why:* Prevents mislabelled "end-to-end encrypted" files, ciphertext-garbage
  downloads, and dedup bypass at Level 2 (§1.4).
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
  `apiEditFile`: when `MaxExpiryDays > 0`, reject-or-clamp `UnlimitedExpiry=true`
  and clamp `ExpiryTimestamp` to `now + max`. Export/reuse the existing helper —
  one policy, two call sites; align with W3's validation choke point if the
  signatures allow.
- *Touches:* `internal/webserver/api/Api.go:82-131`;
  `internal/webserver/fileupload/FileUpload.go` (export clamp helper); tests.
- *Effort:* S. *Risk:* low. *Deps:* none. *Upstreamable:* yes — it completes the
  `GOKAPI_MAX_EXPIRY_DAYS` feature.
- *Build vs. buy/borrow:* reuse of the fork's own clamp helper; nothing external.
- *Acceptance:* with `GOKAPI_MAX_EXPIRY_DAYS=30`: `files/modify` with
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
  `GOKAPI_MAX_EXPIRY_DAYS=<Q1 value>` (`Environment.go:58`, enforcement
  `FileUpload.go:171-183`); `GOKAPI_DISABLE_HOTLINKS` (W4);
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
  **Documented residual risks:** plaintext chunk/temp files on the data mount during
  upload (§1.3); Postgres TLS check runs at setup time only — an operator
  hand-editing `config.json` later bypasses it (accepted; config is
  operator-controlled).
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

**W10 — Branding via the `custom/` mount [decision-independent]**
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

### GATE G1 — Encryption-level decision (POINT OF NO RETURN)

Not a work item — a decision gate that must be passed before Phase 3 is built and
before any real client file is uploaded.

**Why it is a point of no return:** changing the encryption level on a live system
is destructive. Re-running setup with a changed encryption setting generates a new
config and sets `DeleteEncryptedStorage = true`
(`internal/configuration/setup/Setup.go:640-651`), deleting all already-encrypted
files; the docs say the same (`docs/setup.rst:333`). There is no
migrate-between-levels tooling. **The last safe moment to decide is before the
first real client upload.** Discovering this after loading client data would mean
losing or re-collecting everything.

**Inputs to the decision:** the §1.5 decision brief, W1's verified runtime results,
and the risk-appetite question in §5-Q0. **Outputs:** if **Level 2** → build W6 and
W11 (Phase 3 as written), W20 runs the key drills. If **Level 3** → W6/W11 are
cancelled, the Level-3 bucket in §1.5 re-opens (sealed-box inbound or accepting
guest-inbound plaintext), W14 becomes hot-path relevant, and the download-UX
regressions in §1.5 are accepted. Either way the Phase 0-2 work above ships
unchanged — that is what the decision-independent partition is for.

### Phase 3 — Encryption-dependent build (contents decided by G1)

As written, this phase assumes G1 confirms Level 2. If G1 chooses Level 3, this
phase is replaced by the Level-3 bucket in §1.5 and W6/W11 are cancelled.

**W6 — Master key from an external secret source + dual-key rotation (Azure Key Vault via env var) [Level-2-specific — build only after G1 confirms Level 2]**
- *Why:* Highest-value compliance item and the replacement for the cancelled sealed-box
  work. Today the choice is: key in `config.json` on the same Azure Files share as the
  ciphertext (`models/Configuration.go:29-35`; `Setup.go:644-651` generates it), or
  interactive stdin at startup (`Encryption.go:80-84`) which breaks unattended container
  restarts. Neither is defensible for PHI-adjacent data.
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
- *Deps:* W1. *Upstreamable:* yes — "key from env var" and dual-key fallback are
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
  request a range, get a 200 full body, and mis-assemble a corrupt file. (Confirm actual
  behaviour in W1-h.)
- *Design:* only set the header on paths that honour ranges.
- *Effort:* S. *Risk:* low. *Deps:* W1-h. *Upstreamable:* yes.
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
  3. **Key drills** (Level-2 path, if G1 confirms): wrong key at startup → the W6
     canary refuses loudly; lost key → documented recovery from Key Vault
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
- *Effort:* L (mostly operational). *Risk:* none to code. *Deps:* W6 (if L2), W8;
  G1 decided. *Upstreamable:* no (runbook).
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
  retention: `GOKAPI_MAX_EXPIRY_DAYS` clamp + hourly `CleanUp`
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

**W14 — WASM downloader buffer fix (upstream courtesy) [decision-independent — becomes hot-path relevant if G1 chooses Level 3]**
- *Why:* `cmd/wasmdownloader/Main.go:93` allocates a fresh 1 MiB buffer per `Read`
  while `sio.DecReader.Read` returns ≤ one 16 KiB package per call → ~97 % waste.
  Unreachable in our deployment (§1.2) but a two-line fix (hoist the buffer out of the
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

## 3. Work-item counts

| Phase | Items | IDs |
|---|---|---|
| 0 — Verify provisional assumptions | 1 | W1 |
| 1 — Decision-independent correctness & capture | 7 | W7 W2 W3 W4 W5 W17 W18 |
| 2 — Decision-independent platform & hardening | 4 | W8 W9 W10 W21 |
| **G1 — Encryption-level decision** | gate | (point of no return — before any real data) |
| 3 — Encryption-dependent build (if Level 2) | 2 | W6 W11 |
| 4 — Pre-go-live operational gate | 1 | W20 |
| 5 — Deferred compliance apparatus & hygiene | 6 | W15 W16 W12 W13 W14 W19 |
| **Total** | **21** | |

Go-live requires: Phases 0-2 complete, G1 decided, Phase 3 (as decided) complete,
W20 gate passed. Phase 5 follows go-live and is the written gap register for the
deferred compliance project.

## 4. CANCELLED / NOT-DOING / ACCEPTED-RISK (explicit)

| Item | Status | Reason |
|---|---|---|
| X25519 / NaCl sealed-box inbound encryption (branch purpose) | **SHELVED pending G1** (was CANCELLED) | The encryption-level decision is now provisional (§1). Under Level 2 it stays cancelled — inbound at-rest protection comes from server-side encryption (§1.1) + W6. It returns only if G1 chooses Level 3/hybrid. Risk re-rated after the yopass Secret Requests review (§1.5): design risk down (published design, live reference, fingerprint-in-fragment verification), large-file streaming risk unchanged and undemonstrated (512 KB reference cap). Grep confirms none of it was ever implemented here. |
| Level 3 E2E hardening (guest-E2E UX, key recovery UX, Firefox truncation) | **SHELVED pending G1** | Same condition as above; W3 meanwhile blocks E2E assertions at non-E2E levels. |
| **Malware scanning / AV (Q6)** | **CANCELLED — user decision, recorded as ACCEPTED RISK** | User's rationale: "some documents cannot be uploaded outside." **Factual note the user should see before this becomes permanent:** ClamAV (clamd) would run *inside* the deployment — it downloads signature definitions from a CDN but never transmits file content to any third party — so if the concern is third-party transmission, it may not apply to a local scanner. The decision stands unless the user revisits it. **Compensating controls in place:** 30-day hard expiry (Q1 + W17 closing the edit hole), download caps (W2), uploads are never executed server-side and inline views get `Content-Security-Policy: sandbox` (`Headers.go:19-21`), hotlinks disabled entirely (W4), guest upload count/size caps (`Environment.go:63-70`), OIDC-gated admin (W9), and full access audit (W7). Codex ranked missing AV #3 — this row is the documented decision, not an oversight. |
| streamSaver `{size: N}` download-progress fix | **NOT-DOING under the Level 2 assumption** | WASM path not rendered at Level 2 + local (`Webserver.go:582`, `html_download.tmpl:37,59`). Returns to scope if G1 chooses Level 3. |
| ChaCha20-Poly1305 stream-cipher switch | **NOT-DOING** | Server-side decrypt runs native Go with hardware AES-GCM; a format break orphans ciphertext and diverges from upstream `sio-go` usage (`Encryption.go:245-256`) for no user-visible gain. |
| Trillian / Sigstore Rekor / immudb as audit backbone | **NOT-DOING** | W15 build-vs-buy table: separate stateful services (or a public-transparency posture wrong for PHI-adjacent data) that a 4-user deployment cannot justify; `transparency-dev/merkle` recorded as upgrade path. |
| Azure WORM as the *sole* audit mechanism | **NOT-DOING** | Fails the user's "signed and verified" requirement (no offline cryptographic verifiability), leaves the no-cloud default with nothing, kills upstreamability. It is one W15 backend, adding prevention atop detection. |
| RFC 3161 timestamping / external witness | **DEFERRED — recommendation in W15/Q8(d)** | Disproportionate now; monotonic seq + signed checkpoints + WORM ingestion timestamps bound backdating. Triggers to revisit: auditor/contract demand, or threat model covering operator+storage-admin collusion. Interim: quarterly checkpoint-hash export (W20). |
| Distributed / IP-based abuse controls beyond what exists | **PARTIAL — ACCEPTED RISK while single-instance (Q4)** | What exists (verified): guest file-count/size caps (`Environment.go:63-70`), UUID-reservation limiter for unlimited file requests (`Api.go:394-400`), download-password rate limiter (`Webserver.go:604`), disk floor (`MinFreeSpaceMB`). The limiter store is process-local (`ratelimiter/RateLimiter.go:38-44`) — irrelevant at one instance. Added now: W8 storage/request alerts. A distributed limiter is on the W8 scale-out checklist, not built speculatively. |
| Hashing bearer tokens at rest | **PROMOTED to W21** (was DEFERRED) | Q5 decided yes. Removed from this list. |
| yopass as a platform replacement | **NOT-DOING (considered and closed)** | File cap 512 KB default / 1 MB hard without licence vs MB-GB medical documents; expiry presets only 1h/1d/1w — incompatible with Q1's 30-day retention; OIDC, audit logging, secret requests, webhooks, read receipts, theming all licence-gated; and even the licensed audit log has no signing or tamper-evidence, so the standing "signed and verified" requirement cannot be bought there. Its Secret Requests design and several patterns are harvested instead (§1.5). |
| Read-only split deployment (yopass `--read-only` pattern) | **DEFERRED** | Assessed: the attack-surface win is smaller for Gokapi than for yopass because flow 2 (file-request inbound) requires a public WRITE path by definition — a retrieval-only public instance breaks the product. The residual win — an "admin-off" public instance with `/login`, `/admin` and the admin API disabled — is a plausible small upstreamable flag, but conflicts with Q4 (single instance) today. Recorded on the W8 scale-out checklist for re-evaluation. |
| Webhook payload hygiene (hashed id, HMAC-SHA256 + constant-time compare, backoff, stable delivery ID) | **RECORDED as precedent, no work item** | Gokapi has no outbound webhooks/notifications today; if one is ever added, the yopass scheme is the template (§1.5). |
| F7 residual upsert asymmetries (`Users.Name`, `ApiKeys.PublicId`) | **NOT-DOING now** | Low severity; Postgres refusal is safer than SQLite clobber; surfaces only on operator rename collisions. Revisit if hit. |
| S3Proxy / Azure Blob storage backend | **DEFERRED** | Local storage chosen. Warning stands: S3-style storage flips `RequiresClientDecryption()` true again (`FileList.go:159`) — re-run the §1.1 analysis before adopting. |
| Scale-out beyond one instance | **DEFERRED — Q4 decided "single instance for now"** | W8 records the full per-instance checklist (W2, downloadstatus, SSE, rate limiter, CleanUp timer, audit seq writer, ARR affinity) so a future scale-out is a checklist, not a rediscovery. |

## 5. Decision register (settled) and open questions

**Settled by the user — recorded, not re-litigated:**

1. **Q1 — Retention: `GOKAPI_MAX_EXPIRY_DAYS=30`.** Consequences folded in: 30 d
   (vs the earlier 7-d assumption) strengthens the case for W6's dual-key
   rotation (a full key generation now takes a month to age out) and lengthens
   the leaked-link exposure window — so W8 sets staff-facing *defaults* low
   (recommend 7-day expiry preset, small download counts); 30 is the ceiling,
   not the norm. Requires W17, or the cap is fiction on the edit path.
2. **Q2 — Downloader IP logging: YES**, implemented with PIPEDA controls in W7
   (purpose limitation, full-IP-vs-hash analysis with reasons, privacy notice,
   PI-repository handling, retention per Q8(b)).
3. **Q4 — Single App Service instance, for now.** W2 remains a correctness fix
   but not a launch gate; scaling without it silently breaks one-time links;
   W8 carries the scale-out checklist.
4. **Q5 — Hash session tokens & API keys at rest: YES** → W21, behind a
   replaceable credential seam per the user's plugin note.
5. **Q6 — No malware scanning** → accepted risk, §4 row (with the local-ClamAV
   factual note the user should read once).
6. **Q7 — Upstreaming: build first, extract later.** Commit-hygiene rule in §2:
   one concern per commit, upstreamable vs company-specific split (W15, W21
   called out), no history rewriting. AGPL §13 offer independent of upstreaming
   (W12).
7. **Q8(a) — Audit sink failure: FAIL CLOSED**, best-practice shape: durable
   fsync'd LOCAL commit before serving (W7), async shipping with spool, alerts,
   FAU_STG.4 "prevent auditable events" on exhaustion, auditable break-glass
   (W15).
8. **Q8(c) — Audit signing key in Azure Key Vault**, with the honest guarantee
   statement in W15 (prevents exfiltration/offline forgery; does NOT stop a live
   compromised app from signing; WORM sink is the proportionate control that
   protects committed history).

**Open — needing a human decision:**

- **Q0 (G1) — Encryption level: Level 2 vs Level 3 vs hybrid.** THE open
  decision; brief in §1.5; point of no return before first real upload
  (`Setup.go:640-651`). Everything in Phases 0-2 proceeds regardless.
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

## 6. Traceability

Every finding, requirement, Codex review point and user decision maps to a work
item, an accepted risk, or an explicit rejection with reason.

### 6.1 Original findings and requirements

| Finding / requirement | Disposition |
|---|---|
| Level 2 core assumption (server decrypt, progress, no WASM, dedup) | Confirmed statically (§1.1 citations); runtime check W1. **Now provisional** — feeds the §1.5 brief and G1. Docs-vs-code progress discrepancy (`docs/setup.rst:321`) resolved by W1-c. |
| F1 — guest/file-request uploads plaintext under E2E | Resolved **under the Level 2 assumption** (`FileServing.go:500-514`, verified W1-g). REOPENS as the central Level 3 defect if G1 goes that way (§1.5). |
| F2 — client-asserted `isE2E` | **W3** (Level-2 impact reassessed §1.4: integrity/labelling, not plaintext). |
| F3 — panic on transient DB error | Fixed (`b2b2f2f`): retries + recycling (`postgres/Postgres.go:17-96, 172-176`). |
| F4 — no TLS to Postgres / bearer secrets in DB | TLS fixed (`Setup.go:951-963`). Bearer-token residual **promoted to W21** (Q5 decided). Setup-time-only TLS check documented in W8. |
| F5 — DSN password in logs | Fixed (`Database.go:388-398`, `Migration.go:26-27`). |
| F6 — non-atomic, non-floored download cap | **W2**; per Q4 not a launch gate, blocking for any scale-out (W8 checklist). |
| F7 — upsert conflict-target drift | `SaveHotlink` fixed (`b2b2f2f`); residual Low items not-doing with reason (§4). |
| F8 — uint64 traffic vs BIGINT | Fixed (clamp, `b2b2f2f`). |
| F9 — spurious empty E2EConfig rows | **W13**. |
| Zero-nonce AES-GCM | Safe via fresh key per file (verified); invariant locked by **W5** (also guards the E2E client path). |
| Unsalted on-disk filename | Not applicable at Level 2 (salt applied when encryption requested, `FileServing.go:242, 471, 493`; verified W1-a). Note per Codex: the salt is config-resident, so it defends against directory-listing content confirmation, not against an attacker who also has the config. |
| Master key handling / Key Vault | **W6** — Level-2-specific, built only after G1; env-var key source + KV reference + dual-key rotation (Q3 recommendation) + startup canary; drilled in W20. |
| Missing download progress / streamSaver fix | Moot under Level 2 (§1.2); returns if G1 → Level 3 (§4). |
| WASM 1 MiB-per-read allocation (`wasmdownloader/Main.go:93`) | **W14**; becomes hot-path relevant under Level 3. |
| ChaCha20-Poly1305 | Not-doing with reason (§4). |
| Hotlinks auto-created; company wants OFF | **W4** — disable via env var AND mandatory purge of existing valid hotlinks (Codex correction; `cleanHotlinks` only removes dead ones, `FileServing.go:903-912`); edit-path re-add covered (`Api.go:121-126`). |
| Audit logging review (who/what/when) | **W7** — full inventory of `Logging.go:232-341`; six named gaps closed; forward-compatible chained record format from day one; durable fail-closed local write (Q8(a)). |
| Signed, tamper-evident audit log | **W7 (chain now) + W15/W16 (signing, WORM sink, verifier — deferred to Phase 5 by the user's scope decision)**. Deferral cost stated in W7: pre-first-checkpoint events are protected only against post-checkpoint tampering; recommendation: chain from first deployment. |
| Audit best-practice grounding with citations | **W15** standards section (NIST SP 800-92, RFC 8032, RFC 6962 assessed, RFC 3161 deferred, journald-FSS assessed, Trillian/Rekor prior art) + FAU_STG.4 for exhaustion behaviour. |
| Pluggable audit sink, not Azure-only | **W15** — `AuditSink` interface retained; v1 backends cut to local file + Azure WORM (Codex proportionality accepted); S3 Object Lock and stream backends dropped from v1 with the S3Proxy caveat recorded. |
| Audit signing key custody | **Q8(c) decided** (Key Vault) + W15 honesty statement (Codex's forward-security correction accepted); separate key/lifecycle from master key. |
| Build-vs-buy/borrow on every item | §2 rule + per-item lines + W15 comparison table. |
| Custom UI / branding | **W10** (mechanism verified; no fork needed). |
| OIDC/SSO + MFA posture | **W9** (existing `go-oidc` config; `OnlyRegisteredUsers`; MFA at Google). |
| Retention/disposal/breach docs | **W12 — deferred to Phase 5 with the compliance project** (user scope decision); interim minimums live in W20's tabletop. |
| "Nothing may linger" | **NOT yet fully enforced — corrected per Codex.** Creation paths clamped (`fcb5ed3`, `FileUpload.go:171-183`); edit path open until **W17** (`Api.go:99-114`); plus hourly `CleanUp`, revoke-then-clean delete (verified `FileServing.go:987-1002`), Q1 = 30 d, W20 resurrection test. |
| Azure App Service constraints | **W8** (no SQLite on the share; Postgres done; mounts/env/non-root/alerts/backup; single instance per Q4). |
| AGPL §13 | **W12** + Q7 note (obligation independent of upstreaming). |
| Committed work (35eccd1, b2b2f2f, fcb5ed3) | Verified present and built upon; `fcb5ed3` found **incomplete** on the edit path → W17. |
| Test baseline must not regress | §2 rule; acceptance tests add to the 47/47/45 baseline. |
| `Accept-Ranges` advertised but ignored on decrypt path | **W11** (Level-2-specific). |
| Plaintext chunk/temp window during upload | Documented residual risk (§1.3, W8). |

### 6.2 Codex review points (adjudication summary; full record in PLAN-RECONCILIATION.md)

| Codex point | Adjudication |
|---|---|
| Expiry not enforced on edit path (`Api.go:99,107`) | **ACCEPTED — verified** (`Api.go:99-114`) → W17; traceability corrected above. |
| W4 "cleanHotlinks" won't remove live hotlinks | **ACCEPTED — verified** (`FileServing.go:903-912`) → W4 mandatory purge. |
| Key Vault forward-security claim false | **ACCEPTED — the original W15 wording overclaimed**; corrected honesty statement in W15 (managed identity holds signing authority; WORM protects committed history). |
| W2 acceptance test can't run two providers against global `ServeFile` | **ACCEPTED — verified** (`Database.go:16-25` global) → acceptance split into provider-level race + single-process serving + staged two-process check. |
| Level 2 statics correct; salt is config-resident not secret | **ACCEPTED** — noted in §6.1. |
| Progress docs-vs-code discrepancy | Already flagged; W1-c verifies. |
| Phase 0 doesn't de-risk ops | **PARTIALLY ACCEPTED** — drills need W6/W8 to exist; they form W20, and W1 stays scoped to the Level-2 semantics that gate everything else. |
| Governance before PHI | **PARTIALLY ACCEPTED, then superseded** by the user's scope decision (compliance later): engineering gates (G1, W20) precede data; W12 policy work deferred deliberately with the gap register (Phase 5). |
| W6 needs key recovery/rotation first | **ACCEPTED** → W6 now contains the Q3 analysis (dual-key recommended) and W20 drills gate go-live. |
| W8 defers scale-out while W2 targets it | **RESOLVED by Q4** (user: single instance) — W2 reframed as correctness + scale-out precondition, checklist in W8. |
| W3 effort S→M (choke point returns no error) | **ACCEPTED — verified** (`CreateUploadConfig` returns only `UploadParameters`) → M. |
| Gap 1 backup/DR | **ACCEPTED** → W20. |
| Gap 2 key lifecycle | **ACCEPTED** → W6 + W20. |
| Gap 3 malware | **OVERRIDDEN BY USER (Q6)** → accepted risk, §4, with local-ClamAV factual note. |
| Gap 4 abuse controls | **PARTIALLY ACCEPTED** — existing controls verified and cited; W8 alerts added; distributed limiting rejected while single-instance (Q4), on the scale-out checklist. |
| Gap 5 privacy ops (DSAR) | **ACCEPTED IN DESIGN** — W7 PI controls now; procedures in W12 (deferred); Q8(b) carve-out. |
| Gap 6 session hardening | **ACCEPTED — verified** (`SessionManager.go:17, 85-95`) → W18. |
| Gap 7 supply chain/CI | **ACCEPTED — verified** (`test-code.yml:17-20`) → W19. |
| Gap 8 container root | **ACCEPTED — verified** (`dockerentry.sh:2-15`) → W8 non-root. |
| Gap 9 staff isolation | **PARTIALLY ACCEPTED** — permission checks exist (`Api.go:95-98, 718-721`); W20 line 6 adds cross-user spot-checks; a formal role matrix goes to W12. |
| W15/W16 overengineering | **PARTIALLY ACCEPTED** — scope cut (two sinks, KV signer, no Merkle/Trillian) and deferred to Phase 5; full replacement by managed logging REJECTED because it cannot satisfy the user's standing "signed and verified/offline-verifiable" requirement (reason recorded in W15). |
| Effort corrections | **ACCEPTED** for W3, W4, W6, W7, W8, W9; **MODIFIED** for W15/W16 (XL applied to the old five-sink scope, which was cut; L+M at reduced scope). |
| Challenge to Level 2 rationale | **ACCEPTED in framing** (risk trade, not compliance preference; §1 + §1.5) — and the decision itself is now OPEN at G1 per the user. |
| NO-GO verdict | **PARTIALLY ACCEPTED** — no real data before G1 + W20; decision-independent engineering proceeds meanwhile. |

### 6.3 User decisions

| Decision | Where folded in |
|---|---|
| Level 2 vs E2E to be discussed later | §1 provisional status, §1.5 brief, G1 gate, three-bucket partition on every item. |
| Compliance later, but audit-capable design now | W7 first (non-retrofittable capture, forward-compatible chained schema); W15/W16/W12 → Phase 5 gap register. |
| Q1 30 days | W8 defaults, W6 rotation case, W17 dependency — §5. |
| Q2 IP logging yes, compliantly | W7 (coverage check of `SaveIp`, full-IP analysis, notice, PI handling). |
| Q4 single instance for now | W2 status, W8 scale-out checklist, §4 row. |
| Q5 hashed tokens + future plugin seam | W21 (seam design, futures accommodated, near-zero cost stated). |
| Q6 no AV | §4 accepted-risk row incl. local-ClamAV note and compensating controls. |
| Q7 build-first, separate commits, no squash | §2 commit-hygiene rule; W15/W21 split call-outs; W19 rebase link. |
| Q8(a) fail closed, best practice | W7 (durable local commit before serve) + W15 (spool/shipper/escalation/break-glass, FAU_STG.4). |
| Q8(c) signing key in Key Vault | W15 signer + honest guarantee statement. |
| Coordinator's yopass documentation review (Secret Requests = shipped sealed-box reference; 512 KB asymmetric-flow warning; platform rejection; adoptable patterns) | §1.5 yopass note + revised hybrid risk cells (review requirement retained); §4 rows (platform NOT-DOING, read-only split DEFERRED, webhook hygiene RECORDED); W7 field-set adoption; W18/W8 proxy-TLS nuance (verified: `UsesHttps()` is `ServerUrl`-derived, `Configuration.go:81`); W8 metrics note. Full adjudication in PLAN-RECONCILIATION.md §5. |
