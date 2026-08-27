# PLAN-RECONCILIATION — adjudication of the Codex adversarial review and user decisions

Companion to `PLAN.md` (final decided version). Every Codex point is listed with a
verdict — ACCEPT / REJECT / MODIFY — a reason, and where it landed. Codex claims
were re-verified against source before acceptance; verification evidence is cited.
User decisions received during reconciliation (Q1, Q2, Q4-Q8, scope and
architecture notes, and the reopening of the encryption-level decision) are
recorded in §3 and folded into PLAN.md §5/§6.3.

## 1. Codex factual claims — verification results

| # | Codex claim | Verified? | Evidence | Verdict → landing |
|---|---|---|---|---|
| 1 | Expiry cap not enforced on edit path; `fcb5ed3` incomplete | **YES — confirmed** | `apiEditFile` sets `file.UnlimitedTime = true` or arbitrary `file.ExpireAt = request.ExpiryTimestamp` with no clamp (`internal/webserver/api/Api.go:99-114`). `apiDuplicateFile` IS clamped (goes through `CreateUploadConfig`, `Api.go:722-729`). | **ACCEPT** → new **W17**; traceability row "nothing may linger" corrected from "done" to "open until W17". |
| 2 | `cleanHotlinks()` will not remove existing valid hotlinks | **YES — confirmed** | It deletes only hotlinks whose file lookup fails (`FileServing.go:903-912`). | **ACCEPT** → W4 now includes a **mandatory** startup purge of all hotlink rows + `HotlinkId` clearing; also verified the edit-path re-add (`Api.go:121-126`) is covered because it gates on `IsAbleHotlink`. |
| 3 | Key Vault "non-exportable ⇒ container attacker cannot re-sign history" is false | **YES — the original PLAN wording overclaimed** | The app's managed identity holds *signing authority*; a live attacker can invoke `Sign` on forged content without exporting the key. Non-exportability prevents exfiltration/offline forgery after eviction; KV's own audit log records Sign calls. | **ACCEPT** → W15 rewritten with an explicit does/does-not-protect statement; committed-history protection is assigned to the WORM sink + admin separation, not to Key Vault. |
| 4 | W2's acceptance test (two providers driving two `ServeFile` calls) is not expressible | **YES — confirmed** | `ServeFile` uses the package-global provider installed by `database.Connect` (`Database.go:16-25`); one process = one provider. | **ACCEPT** → acceptance split: (a) provider-level race with two directly-instantiated `postgres.DatabaseProvider` values, (b) single-process `ServeFile` denial test, (c) two-process smoke test in staging (W20 line 8). |
| 5 | Session cookie lacks `Secure`; 30-day admin sessions | **YES — confirmed** | `writeSessionCookie` sets `HttpOnly` + `SameSite=Lax` only (`sessionmanager/SessionManager.go:85-95`); `cookieLifeAdmin = 30*24h` (`:17`). | **ACCEPT** → new **W18**. |
| 6 | Container runs as root unless `DOCKER_NONROOT=true` (deprecated) | **YES — confirmed** | `dockerentry.sh:2-15` (marked DEPRECATED in favour of the container user directive). | **ACCEPT** → W8 runs non-root via the supported mechanism. |
| 7 | CI only generates + tests | **YES — confirmed** | `.github/workflows/test-code.yml:17-20`. | **ACCEPT** → new **W19** (govulncheck, dependabot, digest pinning, SBOM, rebase cadence). |
| 8 | Rate limiter is process-local and narrow | **YES, but overstated as "no quotas"** | Limiter store is in-process (`internal/webserver/ratelimiter/RateLimiter.go:38-44`); UUID-reservation limiting at `Api.go:394-400`; download-password limiting at `Webserver.go:604`. BUT guest caps DO exist: `MaxFilesGuestUpload`/`MaxSizeGuestUploadMb` (`Environment.go:63-70`) + `MinFreeSpaceMB`. | **MODIFY** → existing controls cited; W8 adds storage/request alerts; distributed limiting rejected while single-instance (Q4) and placed on the scale-out checklist. |
| 9 | Level 2 statics correct; salt not a defence vs config access | **YES** | Salt is `Authentication.SaltFiles` in config. | **ACCEPT** — noted in PLAN §6.1. |
| 10 | Docs "progress: No" inaccurate for local Level 2 | **Agrees with our own finding** | `Headers.go:24-27` vs `docs/setup.rst:321`. | Already in plan; W1-c verifies empirically. |

## 2. Codex non-factual points

| Point | Verdict | Reason / landing |
|---|---|---|
| NO-GO for PHI as planned | **MODIFY** | Accepted in substance via two hard gates before any real data: **G1** (encryption decision — point of no return, `Setup.go:640-651` destroys encrypted storage on level change) and **W20** (drilled restore/key/authz gate). Rejected as a blanket stop: decision-independent engineering proceeds now, which is what the three-bucket partition is for. |
| Phase 0 doesn't de-risk operations | **MODIFY** | The drills need W6/W8 to exist first; they are W20's checklist, not Phase 0's. W1 stays scoped to the Level-2 semantics every downstream item depends on. |
| Governance must precede PHI | **MODIFY — superseded by user scope decision** | User: compliance work is deferred, but design must keep audit in mind. Landing: engineering gates (G1, W20) precede data; W12/W15/W16 deferred to Phase 5 as a *written* gap register; W7's non-retrofittable capture (chained, canonical, durable) ships first precisely so deferral is safe. |
| W6 unacceptable without recovery/rotation; "rotation orphans ciphertext is destruction" | **ACCEPT** | W6 now contains the Q3 analysis — recommendation: dual-key decrypt fallback (converges within the 30-day retention window) over re-wrap tooling; wrong-key canary; W20 drills key loss/recovery before go-live. |
| W8 defers scale-out that W2 exists for | **RESOLVED by user (Q4: single instance for now)** | W2 reframed: correctness fix now, hard precondition for scale-out; W8 carries the full per-instance checklist (downloadstatus, SSE, rate limiter, CleanUp timer, audit seq writer). |
| W3 effort S→M | **ACCEPT — verified** (`CreateUploadConfig` returns no error; propagation touches `FileUpload.go:133`, `Api.go:488, 722`). |
| Effort: W4→M, W6→L, W7→L, W8→L, W9→M | **ACCEPT** (each justified in the item). |
| Effort: W15/W16 → XL/high | **MODIFY** | XL was fair against the original five-sink/two-scheme scope. That scope is cut (two sinks, one cloud SDK behind a build tag, KV signer per Q8(c)); L+M at the reduced scope, and the whole subsystem is deferred to Phase 5. |
| W15/W16 overengineered; use managed Azure logging + WORM | **MODIFY — the core is kept, the platform is cut** | Managed Log Analytics + locked WORM provide append-only retention but **no offline cryptographic verifiability** — the user's explicit "signed and verified" requirement, which also must work for the no-cloud upstream default (explicit pluggability requirement). Minimum bespoke component: signed checkpoints over the W7 chain + verifier. Everything else is bought (WORM, alerts, key custody). W7 now owns the chain/canonical format from day one so deferring W15 loses nothing structural; the honestly-stated cost: events before the first checkpoint are only protected against post-checkpoint tampering. |
| Gap 1 backup/DR (top gap) | **ACCEPT** → W20 (incl. the resurrection test: restores must not revive expired files). |
| Gap 2 key lifecycle | **ACCEPT** → W6 + W20 drills. |
| Gap 3 malware quarantine | **OVERRIDDEN BY USER (Q6: no AV)** | Recorded as explicit accepted risk in PLAN §4 with the user's rationale, the factual note that ClamAV would run locally and transmit no content to third parties (relevant if their concern was third-party transmission), and the compensating-control list. |
| Gap 4 abuse controls | **MODIFY** — see factual row 8. |
| Gap 5 privacy ops / DSAR | **ACCEPT in design** → W7 PI controls + Q8(b) carve-out now; procedures in W12 (deferred with compliance project). |
| Gap 6 sessions | **ACCEPT** → W18. |
| Gap 7 supply chain | **ACCEPT** → W19. |
| Gap 8 container root | **ACCEPT** → W8. |
| Gap 9 staff isolation | **MODIFY** — permission checks exist (`Api.go:95-98, 718-721`, owner-filtered listing); W20 line 6 adds cross-user authz spot-checks; formal role matrix belongs to W12. |
| Challenge to the Level 2 rationale | **ACCEPT the framing critique; decision reopened by the user anyway** | §1 reclassified provisional; §1.5 decision brief added (blast radius, guest-inbound plaintext under L3, hybrid at XL/high risk, and an honest recompute noting Q6 removed the "Level 2 enables AV" argument). Neither statute mandates E2E — risk appetite, not compliance. Decision taken at G1, before any real data. |

## 3. User decisions folded in during reconciliation

- **Encryption level: OPEN** ("we will discuss e2e and server key later") → §1
  provisional, §1.5 brief, G1 gate, every item bucketed decision-independent /
  Level-2-specific (W6, W11) / Level-3-shelved (sealed-box), decision-independent
  work sequenced first.
- **Compliance later, audit-capable design now** → W7 promoted (capture is
  non-retrofittable; chained canonical schema from day one), W15/W16/W12 deferred
  to Phase 5 as the written gap register; cheap structural controls (W17, W18, W4,
  W21, non-root, abuse alerts) retained.
- **Q1 = 30 days** → W8 staff defaults (recommend 7-day preset), strengthens W6
  dual-key recommendation; meaningless without W17.
- **Q2 IP logging = yes** → W7: `SaveIp` coverage verified (downloads only —
  `Logging.go:280-286`; extended to uploads/denials), truncation/hashing analysed
  and rejected with reasons, privacy notice, PI-repository handling.
- **Q4 single instance** → W2 not launch-gating; W8 scale-out checklist.
- **Q5 hashed tokens = yes, behind a plugin-ready seam** → W21 (SHA-256, indexed
  lookup preserved incl. Redis key names — verified `redis/apikeys.go:12-36`,
  `redis/sessions.go:27-29`; one `CredentialStore` seam, one default impl, seam
  cost ≈ zero; migration keeps existing tokens valid — only re-display is lost).
- **Q6 no AV** → accepted risk (§4) with local-ClamAV factual note.
- **Q7 build-first, separate commits, no squash** → §2 commit-hygiene rule; W15
  and W21 upstreamable/company-specific commit splits called out; W19 rebase link.
- **Q8(a) fail closed, best practice** → W7 durable local fsync-before-serve +
  W15 async shipper/spool/escalation/break-glass; FAU_STG.4 "prevent auditable
  events" + NIST SP 800-92 cited for the exhaustion behaviour.
- **Q8(c) signing key in Key Vault** → W15, with the corrected (non-overclaiming)
  guarantee statement.
- **Still open:** Q0/G1 (encryption level — the single most important pending
  decision), Q3 (rotation: dual-key recommended), Q8(b) (365-day LOCKED window +
  2-year retention recommended), Q8(d) (defer witness/TSA; triggers stated).

## 4. Net effect on the plan

21 work items across Phases 0-5 plus gate G1 (was 16/4 phases). New: W17
(edit-path expiry clamp), W18 (session hardening), W19 (supply chain), W20
(pre-go-live operational gate), W21 (hashed tokens behind a credential seam).
Restructured: W15/W16 simplified and deferred to Phase 5; W12 deferred to Phase 5;
W6/W11 gated behind G1; audit chain/canonical format moved forward into W7.
Corrected overclaims: retention enforcement (W17), hotlink cleanup (W4), Key Vault
forward security (W15), W2 acceptance test. Efforts re-rated per §2 above.

## 5. Late material input: yopass documentation review (coordinator, all 14 pages)

Adjudicated and folded into PLAN.md:

- **Hybrid/sealed-box risk re-rated in §1.5 (ACCEPT):** yopass "Secret Requests"
  is a shipped reference implementation of the cancelled sealed-box design (ECC
  keypair in requester browser; public key registered server-side; responder
  verifies the key against a **fingerprint carried in the URL fragment** before
  client-side OpenPGP encryption; management-token-gated retrieval/revocation/
  rotation; atomic CAS one-time deletion; documented REST API). Table cells for
  the hybrid option revised: design risk lowered ("published design with live
  reference", fingerprint step partially answers the hostile-host objection —
  partially, since a hostile server can still ship malicious JS at decrypt
  time); independent review requirement retained per instruction.
- **Countervailing warning recorded (ACCEPT):** yopass caps the asymmetric
  request flow at 512 KB, database-backend only — while ordinary uploads may use
  disk/S3 and larger sizes. Flagged in §1.5 as a genuine scale warning: the
  MB-to-GB streaming design our use case needs is exactly what the reference
  does not demonstrate; a size-realistic spike is mandatory before committing to
  hybrid at G1.
- **yopass as platform replacement — considered and closed (§4 row):** size
  caps, 1h/1d/1w expiry presets vs Q1=30d, licence-gated OIDC/audit/requests/
  webhooks/theming, and no signing/tamper-evidence even in the licensed audit
  log (fails the standing "signed and verified" requirement).
- **Patterns evaluated individually:**
  - Audit field set → **ADOPTED into W7** (outcome success/failure/denied;
    user email + OIDC subject when authenticated; config metadata one-time/
    expiry/password-protected; error description on failure; never content).
  - Reverse-proxy TLS / `X-Forwarded-Proto` → **ADOPTED into W18/W8 with a
    verified correction:** Gokapi does not inspect `X-Forwarded-Proto`;
    `UsesHttps()` derives from the configured `ServerUrl` prefix
    (`Configuration.go:81, 109-111`), so the `Secure` cookie gating works behind
    the App Service TLS terminator iff `ServerUrl` is `https://` — W8 pins the
    setting, W20 spot-checks the cookie.
  - Read-only split deployment → **DEFERRED (§4 + W8 scale-out checklist):**
    flow 2 requires a public write path, so the yopass win shrinks to an
    "admin-off" public instance; conflicts with Q4 single-instance today.
  - Webhook payload hygiene → **RECORDED as precedent only** (no webhooks exist).
  - Separate metrics port → **NOTED in W8, not applicable** on App Service's
    single exposed port; Azure Monitor instead.
