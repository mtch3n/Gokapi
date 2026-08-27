# HANDOFF — filedrop (Gokapi fork)

Written 2026-08-27. Read this first when resuming. `PLAN.md` is the detailed plan;
`PLAN-RECONCILIATION.md` records how an external review of it was adjudicated;
`SECURITY-ANALYSIS.md` is the original security review.

## What this is

A self-hosted **temporary** file-exchange point for a healthcare-adjacent company
(PIPEDA, HIPAA-adjacent). Google Drive stays as storage; this is **not** storage. Three
flows: send files to clients, ask clients to upload to us, internal exchange. Nothing may
linger. Base is a fork of Gokapi (AGPL-3.0, Go).

## Where everything is

| Thing | Path |
|---|---|
| Fork (all code work) | `~/Work/gokapi-fork`, branch `feat/sealed-box-inbound` |
| GitHub fork | `github.com/mtch3n/Gokapi` — **nothing pushed yet, all local** |
| Upstream remote | `upstream` → `github.com/Forceu/Gokapi` |
| Running deployment | `~/Work/filedrop/` (docker compose, image `filedrop:dev`) |
| Branding (never in fork) | `~/Work/filedrop/custom/` |
| Admin credentials | `~/Work/filedrop/.admin-credentials` (0600) |
| Google OAuth client | `~/Work/filedrop/.oauth-credentials` (0600) — for W9 |
| Per-item worktrees | `~/Work/gokapi-wt/{w2,w3,w4,w5,w7,w18,w22}` — safe to delete |

Live instance: **http://127.0.0.1:53842**, user `admin`. Level 2 encryption, SQLite,
local storage, IP logging on. **Disposable demo** — rebuild once G1 is decided.

## Working agreement

Implement → tests pass → `docker build` → restart the container → tell the user it is
testable and exactly what changed and how to verify it. Each work item is its own
self-contained commit so it can be extracted into an upstream PR later. Do not squash or
rewrite history. **Theme/UI is never upstreamed and must stay out of the fork entirely.**

## Decisions already made

| # | Decision |
|---|---|
| Q1 | Retention `GOKAPI_MAX_EXPIRY_DAYS` = **30** |
| Q2 | **Log downloader IPs** — yes, with PIPEDA controls |
| Q4 | **Single App Service instance** for now |
| Q5 | **Hash session tokens and API keys** at rest (SHA-256, not bcrypt — high-entropy tokens) behind a replaceable seam |
| Q6 | **No AV scanning** — accepted risk, recorded. (ClamAV would run locally and send nothing offsite, if that was the concern) |
| Q7 | Build ours first, upstream later one at a time; separate commits per concern |
| Q8a | Audit fail-closed on **durable local write**; never put a remote sink on the request path |
| Q8c | Audit signing key in **Azure Key Vault** — but be honest it does not stop a compromised app from signing |
| — | Compliance must be **configurable profiles, not mandatory behaviour** (see PLAN §5a) |
| — | Base stays **Gokapi**, not yopass or PrivCloud_Sharing (see PLAN §5b) |
| — | Multi-file: **zip client-side**; no folder concept planned |

**STILL OPEN — G1: encryption level (Level 2 server key vs E2E vs hybrid).** This is a
point of no return: changing it after real data exists deletes all encrypted storage with
no migration path (`Setup.go`). Everything in Phases 0–2 is valid either way. Deadline is
before the first real client file is loaded, i.e. around W8 completion. PLAN §1.5 is the
decision brief.

Also open: **W23** semantics (does issuing or fetching a presigned URL consume the
download; does a zip of five files consume five allowances or one), and whether to do
**W24** (encrypt filenames at rest in the DB — proposed, not yet accepted).

## Done — 9 work items, 28 commits, tests green

Baseline that must not regress: `go generate ./...` first, then
`go test ./... -parallel 8 -count=1 --tags=test,noaws` → **47/47**;
`--tags=test,awsmock` → **47/47**; `--tags=test,noaws,integration` → **45/45**.

- **PostgreSQL provider** (~1500 LOC, 42 methods) + setup wizard + `postgres://` parsing
- **Security hardening**: retry wrappers instead of panic-on-transient-DB-error, TLS
  required for remote Postgres, DSN redaction, upsert conflict-target fix, uint64 clamp
- **W17 + expiry**: `GOKAPI_MAX_EXPIRY_DAYS` on creation *and* the edit path
- **W3**: server rejects the client-asserted `isE2E` flag
- **W18**: `Secure` cookie + `GOKAPI_SESSION_DURATION_DAYS` (default 7, was 30)
- **W4**: `GOKAPI_DISABLE_HOTLINKS` + mandatory purge of existing hotlinks
- **W5**: test-locks the fresh-key-per-distinct-plaintext invariant behind the zero nonce
- **W22**: deduplication restricted to unencrypted storage only
- **W2**: atomic floored download-cap enforcement across all three providers
- **W7**: audit event coverage + hash-chained, forward-compatible record format

## Remaining

**Unblocked now:** W21 (hashed tokens), W10 (branding — pure `custom/`, no fork change),
W9 (Google Workspace OIDC — credentials already stored), W8 (Azure deployment).
**Blocked on G1:** W6 (Key Vault master key), W11 (`Accept-Ranges`), W1 (runtime check).
**Gate:** W20 pre-go-live drills — must now include the corrupt-audit-file drill.
**Deferred:** W15/W16 (signing + verifier), W12 (compliance docs), W13, W14, W19.

## Gotchas — hard-won, do not rediscover

1. **Port 53842**: the `internal/configuration/setup` tests bind it. Stop the `filedrop`
   container before running the full suite, or you get spurious failures.
2. **`go generate ./...`** is required (builds `web/e2e.wasm`) but also causes unrelated
   drift in `build/go.mod` and `docs/advanced.rst` — revert those before committing.
3. **`docs/advanced.rst` is generated** as a fixed-width table; adding one env var reflows
   the whole thing. On a merge conflict, regenerate rather than hand-merging.
4. **The setup wizard only submits selects that were explicitly interacted with**, and
   pressing Back loses state. Driving it in a browser is unreliable. **Instead POST 41
   JSON `{name,value}` pairs to `/setup/setupResult`** — field names come from the
   `form:` struct tags in `Setup_test.go`. This is also how W8 should automate setup.
5. **Do not set the index redirect to `about:blank`** — Go's `html/template` rejects the
   scheme and renders `ZgotmplZ`. Use an http(s) URL.
6. **Postgres provider tests** need
   `GOKAPI_TEST_POSTGRES_URL="postgres://gokapi:testpw@127.0.0.1:15432/gokapi_test?sslmode=disable"`;
   container `gokapi-test-pg`. Without it they skip silently.
7. **Worktrees must be created from the feature branch**, not the default branch. The
   first parallel attempt failed because agents got upstream `master` with no `PLAN.md`.
8. **Parallel agents can conflict semantically while merging cleanly in git** — W5 and
   W22 contradicted each other and only the test run caught it. Always run the full suite
   after each merge, not just at the end.

## Facts worth not re-deriving

- `RequiresClientDecryption()` is `!IsLocalStorage() || IsEndToEndEncrypted`. **Level 2 +
  local storage means the server decrypts**, so there is no WASM in the browser, download
  progress works natively, and mobile is fast. **Switching to S3 flips this back on** and
  the WASM path, slow mobile decryption and missing progress all return.
- WASM is 18.5 MB in the image but loaded **conditionally** (`{{ if .ClientSideDecryption }}`),
  so it costs the browser nothing at Level 2 + local. Do not strip it — that would be a
  large upstream divergence for no user-visible gain, and E2E or S3 would need it back.
- The audit chain's verification rule: `Hash` is the last field with no `omitempty`, so
  **the stored bytes are the canonical pre-image**. Replace the trailing `"hash":"..."`
  value with `""` and hash that. A verifier never re-marshals, so it is Go-version proof.
  W16 must implement exactly this.
- **A fully corrupt audit file currently takes the instance down** (fail-closed writes +
  `auditChainUnusable`), with only a stdout message as the escape hatch. Making
  compliance a profile (§5a) is what resolves this properly.
- Presigned URLs live **30 seconds** and are an internal admin mechanism, not a share
  link. `ServeFilesAsZip` never touches download counters — that is W23.
- SHA-1 collisions are practical; the salt is **appended**, so it does not help against
  them (Merkle–Damgård). Second-preimage is still infeasible, so existing files are safe.
  W22 removed the exposure by not deduplicating encrypted uploads.
