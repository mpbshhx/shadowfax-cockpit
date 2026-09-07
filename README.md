# OpenClaw Operations Cockpit, Phase 1A Core

Local-first, read-only operations cockpit for OpenClaw 2026.9.1. It uses only Node.js 22+ built-ins and refuses every bind address except `127.0.0.1`.

## Scope

Included: Gateway health, source visibility, active work, automation health, bounded Windows storage metadata, cockpit persistence state, minimal evidence timeline, secure local authentication, and cockpit-local acknowledgement.

Excluded: deployment, remote access, config changes, shell/RPC proxying, runtime actions, inventories, projects, cost attribution, backup, and export.

## Start

```powershell
cd app
$env:HOST='127.0.0.1'
$env:PORT='3210'
$env:COCKPIT_DATA_DIR="$PWD\data"
node server.js
```

Open `http://127.0.0.1:3210`. On first run, read `data/auth/bootstrap.token` locally and enroll with a password of at least 12 characters. The token is never printed or returned by HTTP. Save the ten recovery codes when shown. They are shown once.

The process invokes only these structured read-only commands:

* `openclaw gateway call health --json`
* `openclaw gateway call status --json`
* `openclaw gateway call tasks.list --json`
* `openclaw gateway call cron.list --json`

It reads volume capacity and allowlisted file metadata only. It never opens an OpenClaw database.

## Security boundary

* Exact Host: `127.0.0.1:<configured-port>`
* Exact mutation Origin: `http://127.0.0.1:<configured-port>`
* JSON UTF-8 mutations only, 256 KiB body cap
* Server-side 256-bit sessions, SHA-256 digests at rest
* 30-minute idle and 8-hour absolute session expiry
* Session-bound 256-bit CSRF tokens
* Password and recovery verifiers use scrypt N=32768, r=8, p=1, maxmem=64 MiB
* `__Host-cockpit`, HttpOnly, SameSite=Strict, Path=/ cookie. Secure is omitted intentionally in HTTP-only Core.
* No third-party assets and strict CSP

## Verification

```powershell
Get-ChildItem . -Recurse -File -Filter *.js | ForEach-Object { node --check $_.FullName }
npm test
npm run verify
npm run replay
node scripts/canary-harness.js
node scripts/canary-scan.js .. ../evidence/phase1a-canary-scan.json
```

`npm run verify` checks 20 frozen fixture hashes, secret canaries, backup/export absence, and wildcard-bind refusal. `npm run replay` executes all 20 immutable fixture contracts and writes expected-versus-actual records, fixture hashes, and evidence hashes to `../evidence/phase1a-fixture-replay.json`. The canary harness seeds generated values through accepted and rejected synthetic ingress and scans DB, WAL/checkpoint, temp, log, API, UI, and error artifacts.

## Offline auth reset

Stop the server first. Delete only `cockpit-state.json` and `auth/` inside the configured cockpit data directory, leaving diagnostic artifacts untouched, then restart. The server lock makes a second running owner fail closed. Core does not include an online reset endpoint.

## Truthfulness and degraded behavior

Missing, partial, stale, malformed, incompatible, or unreachable critical evidence never renders green. Persistence failure keeps the last verified snapshot available where possible, rejects unsafe mutations, and reports `PERSISTENCE DEGRADED` or `READ-ONLY RECOVERY`.

## Verified residual controls

* Outbound acquisition uses one 8 request/second token bucket with capacity 16, queue 32, keyed noncritical coalescing, and retry delays of 1, 2, 4, 8, and 15 seconds plus bounded jitter only for timeout, transport, and 5xx failures.
* All 20 immutable fixtures replay through one evidence runner and currently pass.
* All six mutation routes exercise Origin, content type, unexpected methods, body cap boundaries, and protected-route authentication and CSRF gates.
* SSE accepts 25 authenticated clients, rejects the 26th, rejects unauthenticated clients, and applies the exact greater-than-256-KiB slow-reader predicate.
* Isolated temp-path tests cover repeated write and checkpoint failure, rollback after an interrupted transaction, corruption read-only recovery, hard admission refusal, and the exact 300-second recovery dwell model.

## Known limits

Persistence uses Node's built-in SQLite API in WAL mode with full synchronous commits, integrity checks, size pre-admission, and checkpointing. The current Windows directory has the intended three principals but inherited ACL protection is not removed, and denial from a separate unprivileged principal was not tested. The 10-minute CPU/RSS sampler failed to complete and remains unverified, as do normal and burst resource gates, a transport-level slow-reader disconnect, RSS restart behavior, complete retention pressure behavior, and cold-operator usability. See `../PHASE-1A-CORE-BUILD-REPORT.md`.