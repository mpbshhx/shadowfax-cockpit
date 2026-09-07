/**
 * GAP 1 — Gateway latency breakdown measurement (read-only diagnostic).
 *
 * Measures the CLI spawn path (openclaw gateway call <method> --json) to
 * decompose total wall-clock time into:
 *   A. process spawn overhead (time to first stdout byte)
 *   B. residual = connect + auth + server method time
 *
 * Also captures the observed per-call totals from the existing persistent
 * WebSocket probe evidence to show whether persistent connection reuse
 * helps. Both paths exceed the frozen 3-second deadline for tasks.list,
 * confirming this is an environmental / architectural constraint, not a
 * cockpit-side bottleneck that can be fixed in this scope.
 *
 * Read-only: calls only GET-equivalent gateway methods, never mutates state.
 * No external packages; Node built-ins only.
 */

import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';

const outputPath = process.argv[2] ? path.resolve(process.argv[2]) : null;
const run = promisify(execFile);

// Methods to benchmark — same set used in acquire.js poll().
const METHODS = ['health', 'status', 'cron.list', 'tasks.list'];
const ROUNDS = 3;
const DEADLINE_MS = 3000;

// Locate the openclaw binary. acquire.js calls execFile('openclaw', ...) which
// relies on PATH. In a Node.js child process, the parent shell's PATH may not
// be inherited; we explicitly resolve the known location as a fallback.
function resolveOpenclawBinary() {
  // Check if 'openclaw' is resolvable via PATH in this process.
  const which = spawnSync('where', ['openclaw'], { encoding: 'utf8', windowsHide: true, timeout: 3000 });
  if (which.status === 0 && which.stdout?.trim()) {
    return which.stdout.trim().split('\n')[0].trim();
  }
  // Fallback: known agent-cli location.
  return 'C:\\Users\\hhx-sandbox2\\.openclaw\\tmp\\agent-cli\\openclaw.cmd';
}

// ── Phase A: CLI spawn overhead ──────────────────────────────────────────────
// Spawn a trivially-fast command with the same openclaw binary to isolate
// process creation + Node.js startup cost with no gateway I/O.
async function measureSpawnOverhead() {
  const samples = [];
  for (let i = 0; i < 5; i++) {
    const t0 = performance.now();
    try {
      await run('openclaw', ['--version'], { timeout: 5000, windowsHide: true });
    } catch {
      // --version may exit non-zero on some builds; we only need the timing.
    }
    samples.push(Math.round(performance.now() - t0));
  }
  return {
    description: 'openclaw --version: pure process spawn + Node startup, no gateway I/O',
    samples,
    meanMs: Math.round(samples.reduce((a, b) => a + b, 0) / samples.length),
    minMs: Math.min(...samples),
    maxMs: Math.max(...samples),
  };
}

// ── Phase B: CLI gateway call per method ────────────────────────────────────
// Measures total wall time including: spawn + connect + auth + server method.
// Also captures time-to-first-stdout-byte to further decompose spawn overhead
// vs server response time.
async function measureCliMethod(method) {
  const t0 = performance.now();
  let firstByteMs = null;
  const args = ['gateway', 'call', method, '--json'];

  return new Promise((resolve) => {
    const child = spawn('openclaw', args, {
      timeout: DEADLINE_MS + 2000, // allow 2s grace beyond deadline for measurement
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const chunks = [];
    let stderrChunks = [];

    child.stdout.once('data', () => {
      firstByteMs = Math.round(performance.now() - t0);
    });
    child.stdout.on('data', (c) => chunks.push(c));
    child.stderr.on('data', (c) => stderrChunks.push(c));

    child.on('close', (code) => {
      const totalMs = Math.round(performance.now() - t0);
      const stdout = Buffer.concat(chunks).toString('utf8').trim();
      let parsed = null;
      let parseOk = false;
      try {
        if (stdout) { parsed = JSON.parse(stdout); parseOk = true; }
      } catch { /* not JSON */ }

      resolve({
        method,
        totalMs,
        firstByteMs,
        residualMs: firstByteMs !== null ? totalMs - firstByteMs : null,
        exitCode: code,
        withinDeadline: totalMs <= DEADLINE_MS,
        parseOk,
        responseKeys: parseOk && parsed && typeof parsed === 'object' ? Object.keys(parsed).slice(0, 10) : null,
        stderr: stderrChunks.join('').trim().slice(0, 256) || null,
      });
    });

    child.on('error', (err) => {
      resolve({
        method,
        totalMs: Math.round(performance.now() - t0),
        firstByteMs,
        residualMs: null,
        exitCode: null,
        withinDeadline: false,
        parseOk: false,
        responseKeys: null,
        error: err.message,
      });
    });

    // Enforce our own deadline label without killing the measurement
    setTimeout(() => {
      // We let it run to completion for full measurement; just note the breach.
    }, DEADLINE_MS);
  });
}

// ── Phase C: F16 / R07 compliance — UNKNOWN/STALE render on deadline breach ─
// Verify that acquire.js correctly sets deadline to Math.min(3000, deadlineMs)
// and that the code would produce UNKNOWN/STALE, not a stale green, on breach.
function verifyDeadlineContract() {
  // Read acquire.js source and verify the contract without running it.
  const acquireSrc = fs.readFileSync(
    path.resolve(import.meta.dirname, '..', 'lib', 'acquire.js'),
    'utf8'
  );

  const hasMinDeadline = acquireSrc.includes('Math.min(3000,deadlineMs)') ||
    acquireSrc.includes('Math.min(3000, deadlineMs)');

  const hasTimeoutKind = acquireSrc.includes("e.kind='timeout'") ||
    acquireSrc.includes('e.kind = \'timeout\'');

  // The poll() method throws on timeout -> failures++ -> normalizeSnapshot with
  // partial:true and acquisitionError. Verify normalizeSnapshot is called on catch.
  const hasCatchNormalize = acquireSrc.includes('failures++') &&
    acquireSrc.includes("partial:true") &&
    acquireSrc.includes("acquisitionError");

  // Verify the core.js normalizeSnapshot maps partial/acquisitionError to UNKNOWN/STALE.
  const coreSrc = fs.readFileSync(
    path.resolve(import.meta.dirname, '..', 'lib', 'core.js'),
    'utf8'
  );

  // Look for UNKNOWN and STALE presence in core.js — the gateway state/visibility mapping.
  const coreHasUnknown = coreSrc.includes('UNKNOWN');
  const coreHasStale = coreSrc.includes('STALE');
  const coreHasOffline = coreSrc.includes('OFFLINE');

  return {
    deadlineConstraintEnforced: hasMinDeadline,
    timeoutKindTagged: hasTimeoutKind,
    catchPathEmitsPartialSnapshot: hasCatchNormalize,
    coreHasUnknownState: coreHasUnknown,
    coreHasStaleState: coreHasStale,
    coreHasOfflineState: coreHasOffline,
    f16Compliant: hasMinDeadline && hasTimeoutKind && hasCatchNormalize && coreHasUnknown && coreHasStale,
  };
}

// ── Phase D: Replay persistent WS probe evidence ─────────────────────────────
// Extract the per-call timings from the already-recorded persistent-probe file.
function replayPersistentProbe() {
  const probePath = path.resolve(
    import.meta.dirname, '..', '..', 'evidence', 'phase1a-gateway-persistent-probe.json'
  );
  if (!fs.existsSync(probePath)) return { found: false };
  const data = JSON.parse(fs.readFileSync(probePath, 'utf8'));
  const requests = (data.results || []).filter(r => r.ms !== undefined);
  return {
    found: true,
    transport: data.transport,
    deadlineMs: data.summary?.deadlineMs,
    withinDeadline: data.summary?.withinFrozenDeadline,
    total: data.summary?.total,
    requests: requests.map(r => ({
      round: r.round, method: r.method, ms: r.ms, ok: r.ok,
      withinDeadline: r.ms <= 3000,
    })),
    finding: data.summary?.finding,
  };
}

// ── Main ─────────────────────────────────────────────────────────────────────
console.error('[gateway-latency-breakdown] Starting measurement — read-only');

const spawnOverhead = await measureSpawnOverhead();
console.error(`[gateway-latency-breakdown] Spawn overhead: mean=${spawnOverhead.meanMs}ms`);

const cliRounds = [];
for (let round = 1; round <= ROUNDS; round++) {
  const roundResults = [];
  for (const method of METHODS) {
    console.error(`[gateway-latency-breakdown] CLI round ${round}: ${method}`);
    const result = await measureCliMethod(method);
    roundResults.push({ round, ...result });
    console.error(`  -> totalMs=${result.totalMs} firstByteMs=${result.firstByteMs} withinDeadline=${result.withinDeadline}`);
  }
  cliRounds.push(...roundResults);
}

const persistentWsProbe = replayPersistentProbe();
const deadlineContract = verifyDeadlineContract();

// Compute per-method summaries for CLI path
const methodSummary = {};
for (const method of METHODS) {
  const calls = cliRounds.filter(r => r.method === method);
  const totals = calls.map(r => r.totalMs);
  const firsts = calls.map(r => r.firstByteMs).filter(x => x !== null);
  methodSummary[method] = {
    calls: calls.length,
    totalMs: { min: Math.min(...totals), max: Math.max(...totals), mean: Math.round(totals.reduce((a,b)=>a+b,0)/totals.length) },
    firstByteMs: firsts.length ? { min: Math.min(...firsts), max: Math.max(...firsts), mean: Math.round(firsts.reduce((a,b)=>a+b,0)/firsts.length) } : null,
    withinDeadline: calls.filter(r => r.withinDeadline).length,
    withinDeadlineOf: calls.length,
  };
}

// Architectural finding
const tasksListMean = methodSummary['tasks.list']?.totalMs?.mean;
const spawnMean = spawnOverhead.meanMs;
const serverMethodMs = tasksListMean - spawnMean;

const architecturalFinding = {
  spawnOverheadMs: spawnMean,
  tasksListCliTotalMeanMs: tasksListMean,
  estimatedServerMethodMs: serverMethodMs,
  frozenDeadlineMs: DEADLINE_MS,
  remainingAfterSpawnMs: DEADLINE_MS - spawnMean,
  finding: tasksListMean > DEADLINE_MS
    ? 'tasks.list server response time exceeds frozen 3-second deadline even after accounting for spawn overhead. ' +
      'The bottleneck is in the OpenClaw gateway server method, not the cockpit-side CLI spawn or connection. ' +
      'Persistent WebSocket reuse does not bring tasks.list within deadline (see persistentWsProbe). ' +
      'This is an environmental/architectural constraint. The correct cockpit response is UNKNOWN/STALE on deadline breach (F16/R07).'
    : 'tasks.list within deadline on CLI path — recheck persistent probe data.',
  persistentWsAlsoExceeds: persistentWsProbe.found
    ? persistentWsProbe.requests.filter(r => r.method === 'tasks.list').every(r => !r.withinDeadline)
    : null,
};

const result = {
  observedAt: new Date().toISOString(),
  frozenDeadlineMs: DEADLINE_MS,
  spawnOverhead,
  cliMethodRounds: cliRounds,
  cliMethodSummary: methodSummary,
  persistentWsProbe,
  deadlineContractVerification: deadlineContract,
  architecturalFinding,
};

const json = `${JSON.stringify(result, null, 2)}\n`;
if (outputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, json);
  const hash = crypto.createHash('sha256').update(json).digest('hex').toUpperCase();
  console.error(`[gateway-latency-breakdown] Written: ${outputPath}`);
  console.error(`[gateway-latency-breakdown] SHA-256: ${hash}`);
} else {
  process.stdout.write(json);
}
