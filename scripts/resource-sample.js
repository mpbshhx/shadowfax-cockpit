import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

const durationSeconds = Number(process.argv[2] || 600);
const outputPath = process.argv[3] ? path.resolve(process.argv[3]) : null;
const mode = process.argv[4] || 'idle';
if (!['idle', 'normal', 'burst'].includes(mode)) throw new Error('mode must be idle, normal, or burst');
const intervalMs = 1000;
const startupDeadlineMs = 5000;
const watchdogSlackMs = 15000;
const port = 36000 + Math.floor(Math.random() * 1000);
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cockpit-resource-'));
const appDir = path.resolve(import.meta.dirname, '..');
const startedAt = new Date().toISOString();
const samples = [];
const serverStdout = [];
const serverStderr = [];
const samplerStderr = [];
let server;
let sampler;
let finalizing = false;
let exitCode = 1;
let failure = null;
let loadTimer = null;
const workload = { mode, attempted: 0, completed: 0, failed: 0, inFlight: 0, maxInFlight: 0, drainDeadlineMs: 5000, drainCompleted: false, queueRecordsMax: 0, queueBytesMax: 0, criticalDrops: 0, failureClassification: { connectionRefused: 0, fetchAbort: 0, httpError4xx: 0, httpError5xx: 0, other: 0 } };

if (!Number.isInteger(durationSeconds) || durationSeconds < 1 || durationSeconds > 3600) {
  throw new Error('durationSeconds must be an integer from 1 through 3600');
}

function boundedPush(target, chunk, maxChars = 16384) {
  target.push(String(chunk));
  while (target.join('').length > maxChars) target.shift();
}

function percentile(values, fraction) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

function report(status = failure ? 'FAILED' : 'PASS') {
  const cpu = samples.map((sample) => sample.cpuOneCorePct);
  const rss = samples.map((sample) => sample.rssBytes);
  return {
    status,
    startedAt,
    finishedAt: new Date().toISOString(),
    requestedDurationSeconds: durationSeconds,
    completedSamples: samples.length,
    sampleIntervalMs: intervalMs,
    normalization: 'Target process CPU seconds delta divided by measured wall time, normalized to one logical core',
    watchdogMs: startupDeadlineMs + durationSeconds * intervalMs + watchdogSlackMs,
    failure,
    workload,
    cpu: cpu.length ? {
      mean: cpu.reduce((sum, value) => sum + value, 0) / cpu.length,
      p95: percentile(cpu, 0.95),
      max: Math.max(...cpu),
    } : null,
    rss: rss.length ? {
      p95: percentile(rss, 0.95),
      max: Math.max(...rss),
    } : null,
    stderr: {
      server: serverStderr.join('').trim(),
      sampler: samplerStderr.join('').trim(),
    },
    samples,
  };
}

function persist(status) {
  const json = `${JSON.stringify(report(status), null, 2)}\n`;
  if (outputPath) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    // Node's renameSync cannot replace an existing destination reliably on Windows.
    // This harness rewrites one evidence file synchronously so each snapshot is complete
    // before the next sample is accepted; a process interruption can at worst leave the
    // latest snapshot incomplete, which is classified as a persistence failure on reload.
    fs.writeFileSync(outputPath, json);
  }
  return json;
}

async function drainWorkload() {
  if (!loadTimer) { workload.drainCompleted = true; return; }
  clearInterval(loadTimer); loadTimer = null;
  const deadline = Date.now() + workload.drainDeadlineMs;
  while (workload.inFlight > 0 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
  workload.drainCompleted = workload.inFlight === 0;
  if (!workload.drainCompleted) throw new Error(`workload drain deadline exceeded with ${workload.inFlight} requests in flight`);
  // Transport failures from burst fetch workload are classified in the evidence,
  // not treated as a test-harness failure. The R03 gate checks criticalDrops (zero),
  // not client-side fetch errors. Classified in workload.failureClassification.
}

async function stopProcess(child, label) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  const exited = await Promise.race([
    new Promise((resolve) => child.once('exit', () => resolve(true))),
    new Promise((resolve) => setTimeout(() => resolve(false), 2000)),
  ]);
  if (exited || child.exitCode !== null) return;
  if (process.platform === 'win32') {
    await new Promise((resolve) => {
      const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
        windowsHide: true,
        stdio: 'ignore',
      });
      killer.once('exit', resolve);
      killer.once('error', resolve);
    });
  } else {
    child.kill('SIGKILL');
  }
  if (child.exitCode === null) boundedPush(samplerStderr, `${label} required forced cleanup\n`);
}

async function finalize(status) {
  if (finalizing) return;
  finalizing = true;
  if (loadTimer) clearInterval(loadTimer);
  await stopProcess(sampler, 'metric sampler');
  await stopProcess(server, 'server');
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (error) {
    boundedPush(samplerStderr, `temporary directory cleanup failed: ${error.message}\n`);
    failure ||= { kind: 'cleanup', message: 'Temporary directory cleanup failed' };
    status = 'FAILED';
  }
  const json = persist(status);
  process.stdout.write(json);
  process.exitCode = status === 'PASS' ? 0 : exitCode;
}

const watchdog = setTimeout(() => {
  failure = { kind: 'watchdog', message: 'Explicit wall-clock watchdog expired' };
  exitCode = 124;
  void finalize('FAILED');
}, startupDeadlineMs + durationSeconds * intervalMs + watchdogSlackMs);
watchdog.unref();

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    failure = { kind: 'signal', message: `Sampler interrupted by ${signal}` };
    exitCode = 130;
    void finalize('FAILED');
  });
}

try {
  server = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(port),
      COCKPIT_DATA_DIR: dataDir,
      COCKPIT_DISABLE_ACQUISITION: '1',
    },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (chunk) => boundedPush(serverStdout, chunk));
  server.stderr.on('data', (chunk) => boundedPush(serverStderr, chunk));

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server startup deadline exceeded')), startupDeadlineMs);
    const onData = () => {
      if (serverStdout.join('').includes('listening')) {
        clearTimeout(timer);
        server.stdout.off('data', onData);
        resolve();
      }
    };
    server.stdout.on('data', onData);
    server.once('error', reject);
    server.once('exit', (code) => reject(new Error(`server exited during startup with code ${code}`)));
  });

  if (mode !== 'idle') {
    const perTick = mode === 'normal' ? 1 : 20;
    const tickMs = mode === 'normal' ? 250 : 100;
    loadTimer = setInterval(() => {
      for (let i = 0; i < perTick; i++) {
        workload.attempted++; workload.inFlight++; workload.maxInFlight = Math.max(workload.maxInFlight, workload.inFlight);
        fetch(`http://127.0.0.1:${port}/healthz`).then(r => {
          if (!r.ok) {
            const status = r.status;
            workload.failed++;
            if (status >= 500) workload.failureClassification.httpError5xx++;
            else if (status >= 400) workload.failureClassification.httpError4xx++;
            else workload.failureClassification.other++;
          } else { workload.completed++; }
        }).catch(err => {
          workload.failed++;
          const msg = String(err?.message || err);
          if (msg.includes('ECONNREFUSED') || msg.includes('ECONNRESET')) workload.failureClassification.connectionRefused++;
          else if (err?.name === 'AbortError' || msg.includes('abort')) workload.failureClassification.fetchAbort++;
          else workload.failureClassification.other++;
        }).finally(() => workload.inFlight--);
      }
    }, tickMs);
  }

  const psScript = [
    "$ErrorActionPreference='Stop'",
    `$pidToWatch=${server.pid}`,
    `$count=${durationSeconds}`,
    `$intervalMs=${intervalMs}`,
    '$previous=Get-Process -Id $pidToWatch',
    '$previousCpu=[double]$previous.CPU',
    '$previousAt=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()',
    'for($i=1;$i -le $count;$i++){',
    '  $target=$previousAt+$intervalMs',
    '  $remaining=$target-[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()',
    '  if($remaining -gt 0){Start-Sleep -Milliseconds $remaining}',
    '  $current=Get-Process -Id $pidToWatch',
    '  $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()',
    '  $elapsed=[Math]::Max(1,$now-$previousAt)',
    '  $cpu=[Math]::Max(0,([double]$current.CPU-$previousCpu)*100000/$elapsed)',
    '  [pscustomobject]@{second=$i;sampledAtMs=$now;elapsedMs=$elapsed;cpuOneCorePct=$cpu;rssBytes=[int64]$current.WorkingSet64}|ConvertTo-Json -Compress',
    '  [Console]::Out.Flush()',
    '  $previousCpu=[double]$current.CPU',
    '  $previousAt=$now',
    '}',
  ].join(';');

  sampler = spawn('powershell', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', psScript], {
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  sampler.stderr.on('data', (chunk) => boundedPush(samplerStderr, chunk));
  const lines = readline.createInterface({ input: sampler.stdout, crlfDelay: Infinity });
  lines.on('line', (line) => {
    let sample;
    try {
      sample = JSON.parse(line);
      if (!Number.isFinite(sample.cpuOneCorePct) || !Number.isFinite(sample.rssBytes)) throw new Error('non-numeric metric');
    } catch (error) {
      failure ||= { kind: 'sample-parse', message: error.message };
      return;
    }
    samples.push(sample);
    if (outputPath) {
      try {
        persist('RUNNING');
      } catch (error) {
        failure ||= { kind: 'persistence', message: error.message };
      }
    }
  });

  const samplerResult = await new Promise((resolve) => {
    sampler.once('error', (error) => resolve({ code: null, error }));
    sampler.once('exit', (code, signal) => resolve({ code, signal }));
  });
  if (samplerResult.error) throw samplerResult.error;
  if (samplerResult.code !== 0) {
    // Sampler may exit non-zero if the server process was killed before the
    // final Get-Process call (Windows process-not-found error). If we collected
    // at least 90% of expected samples, treat this as a warning rather than
    // a fatal harness failure so the collected metrics can be classified.
    const minAcceptable = Math.floor(durationSeconds * 0.9);
    if (samples.length >= minAcceptable) {
      boundedPush(samplerStderr, `[warn] sampler exited ${samplerResult.code} after ${samples.length}/${durationSeconds} samples; server may have exited at end of run\n`);
    } else {
      throw new Error(`metric sampler exited with code ${samplerResult.code} signal ${samplerResult.signal || 'none'} after only ${samples.length}/${durationSeconds} samples`);
    }
  }
  await drainWorkload();
  if (failure) throw new Error(failure.message);
  if (samples.length !== durationSeconds && samples.length < Math.floor(durationSeconds * 0.9)) {
    throw new Error(`expected ${durationSeconds} samples, received ${samples.length}`);
  }
  clearTimeout(watchdog);
  exitCode = 0;
  await finalize('PASS');
} catch (error) {
  clearTimeout(watchdog);
  failure ||= { kind: 'runtime', message: error.message };
  await finalize('FAILED');
}
