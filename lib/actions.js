/**
 * Phase 1B — Run Automation Action Handler
 *
 * Security model:
 * - Compile-time enum of allowed actions (no free-form shell text)
 * - Server-side authorization (valid authenticated session required)
 * - Action-specific permissions via ALLOWED_ACTIONS enum
 * - Exact target allowlist: jobId must exist in live automation list snapshot
 * - Fresh precondition checks: refuse if job appears running/stuck
 * - Stale-page rejection: clientStateVersion must match server stateVersion
 * - CSRF and Origin validated by caller (mutationGate) before this module is reached
 * - Cooldown: 30s per jobId, 60s global
 * - Rate limit: max 3 action requests per 60s per session key
 * - Double-submit: dedupe by idempotencyKey (uuid provided by client)
 * - Intent persistence BEFORE execution
 * - Timeout: 30s hard cap, OUTCOME UNKNOWN on breach
 * - Post-action verification: poll automations runs after 3s
 * - Terminal audit records for all outcomes
 * - No override rule: actions cannot be granted broader Gateway authority
 */

import {spawn} from 'node:child_process';
import {sha, randomToken} from './core.js';

// Compile-time enum of allowed action kinds. Expanding requires code change.
export const ALLOWED_ACTIONS = Object.freeze({
  RUN_AUTOMATION: 'run-automation',
  PAUSE_AUTOMATION: 'pause-automation',
  RESTART_GATEWAY: 'restart-gateway',
});

// Per-jobId cooldown in ms (run-automation)
const COOLDOWN_JOB_MS = 30_000;
// Global cross-job cooldown in ms (run-automation)
const COOLDOWN_GLOBAL_MS = 60_000;
// Per-jobId cooldown in ms (pause-automation — reversible, shorter)
const PAUSE_COOLDOWN_JOB_MS = 15_000;
// Global cross-job cooldown in ms (pause-automation)
const PAUSE_COOLDOWN_GLOBAL_MS = 30_000;
// Rate limit: max requests per window per session
const RATE_LIMIT_MAX = 3;
const RATE_LIMIT_WINDOW_MS = 60_000;
// CLI execution timeout in ms
const EXEC_TIMEOUT_MS = 30_000;
// Post-action verification delay
const VERIFY_DELAY_MS = 3_000;
// Max age for a valid idempotency key to block double-submit (ms)
const IDEMPOTENCY_WINDOW_MS = 120_000;
// Restart gateway cooldown (5 minutes — high-impact, not instantly reversible)
const RESTART_COOLDOWN_MS = 300_000;
// Restart CLI execution timeout (--safe may wait for drain)
const RESTART_TIMEOUT_MS = 90_000;

export class ActionHandler {
  constructor(store) {
    this.store = store;
    // jobId -> timestamp of last trigger
    this._cooldownJob = new Map();
    // timestamp of last global action
    this._cooldownGlobal = 0;
    // jobId -> timestamp of last pause/resume action
    this._pauseCooldownJob = new Map();
    // timestamp of last global pause/resume action
    this._pauseCooldownGlobal = 0;
    // sessionKey -> [{ts}] rate limit window
    this._rateLimits = new Map();
    // idempotencyKey -> {ts, jobId, outcome} double-submit dedup
    this._idempotencyKeys = new Map();
    // in-flight set: jobId -> true (prevents concurrent triggers for same job)
    this._inFlight = new Set();
    // in-flight set for pause: jobId -> true
    this._pauseInFlight = new Set();
    // restart gateway in-flight flag
    this._restartInFlight = false;
    // timestamp of last restart trigger (for 300s cooldown)
    this._restartCooldownAt = 0;
  }

  /**
   * Returns the current state version string based on store snapshot.
   * Used to detect stale page.
   */
  stateVersion(currentSnapshot) {
    // Version is SHA of the snapshot generatedAt + persistence state
    if (!currentSnapshot) return 'no-snapshot';
    return sha(JSON.stringify({
      generatedAt: currentSnapshot.generatedAt || null,
      persistenceState: (currentSnapshot.persistence || {}).state || null,
    }));
  }

  /**
   * Check per-session rate limit. Returns true if over limit.
   */
  _isRateLimited(sessionKey) {
    const now = Date.now();
    const window = this._rateLimits.get(sessionKey) || [];
    // Purge old
    const fresh = window.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
    this._rateLimits.set(sessionKey, fresh);
    if (fresh.length >= RATE_LIMIT_MAX) return true;
    fresh.push(now);
    return false;
  }

  /**
   * Check cooldowns. Returns null if OK, or {error, retryAfterMs} if blocked.
   */
  _checkCooldowns(jobId) {
    const now = Date.now();
    const globalAge = now - this._cooldownGlobal;
    if (globalAge < COOLDOWN_GLOBAL_MS) {
      return {error: 'COOLDOWN_ACTIVE', retryAfterMs: COOLDOWN_GLOBAL_MS - globalAge};
    }
    const jobAge = now - (this._cooldownJob.get(jobId) || 0);
    if (jobAge < COOLDOWN_JOB_MS) {
      return {error: 'COOLDOWN_ACTIVE', retryAfterMs: COOLDOWN_JOB_MS - jobAge};
    }
    return null;
  }

  /**
   * Check idempotency key. Returns the cached outcome if this key was already processed.
   * Returns null if the key is fresh (not seen).
   */
  _checkIdempotency(idempotencyKey) {
    if (!idempotencyKey) return null;
    const now = Date.now();
    this._pruneIdempotencyKeys(now);
    return this._idempotencyKeys.get(idempotencyKey) || null;
  }

  _pruneIdempotencyKeys(now) {
    for (const [k, v] of this._idempotencyKeys) {
      if (now - v.ts > IDEMPOTENCY_WINDOW_MS) this._idempotencyKeys.delete(k);
    }
  }

  _recordIdempotency(idempotencyKey, jobId, outcome) {
    if (!idempotencyKey) return;
    this._idempotencyKeys.set(idempotencyKey, {ts: Date.now(), jobId, outcome});
  }

  /**
   * Validate that jobId exists in the current automations snapshot.
   * Returns the job record or null.
   */
  _findJob(jobId, currentSnapshot) {
    if (!currentSnapshot) return null;
    const jobs = currentSnapshot.automations || [];
    return jobs.find(j => j.id === jobId) || null;
  }

  /**
   * Execute: openclaw automations run <jobId> --json
   * Returns {exitCode, stdout, stderr, timedOut}
   */
  async _spawnRun(jobId) {
    return new Promise(resolve => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      const child = spawn('openclaw', ['automations', 'run', jobId, '--json'], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        timedOut = true;
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
      }, EXEC_TIMEOUT_MS);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.stderr.on('data', d => { stderr += d.toString('utf8'); });
      child.on('close', exitCode => {
        clearTimeout(timer);
        resolve({exitCode: exitCode ?? -1, stdout, stderr, timedOut});
      });
      child.on('error', err => {
        clearTimeout(timer);
        resolve({exitCode: -1, stdout, stderr: stderr + err.message, timedOut: false, spawnError: true});
      });
    });
  }

  /**
   * Execute: openclaw automations runs --id <jobId> --limit 1 --json
   * Returns parsed JSON or null on failure.
   */
  async _spawnRuns(jobId) {
    return new Promise(resolve => {
      let stdout = '';
      const child = spawn('openclaw', ['automations', 'runs', '--id', jobId, '--limit', '1', '--json'], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
        resolve(null);
      }, EXEC_TIMEOUT_MS);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.on('close', exitCode => {
        clearTimeout(timer);
        if (exitCode !== 0) { resolve(null); return; }
        try { resolve(JSON.parse(stdout)); } catch { resolve(null); }
      });
      child.on('error', () => { clearTimeout(timer); resolve(null); });
    });
  }

  /**
   * Parse the CLI stdout into a structured result.
   * Returns {parsed, ok, message} or null if unparseable.
   */
  _parseRunOutput(stdout) {
    if (!stdout || !stdout.trim()) return null;
    // Look for a JSON line
    for (const line of stdout.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('{')) continue;
      try {
        const obj = JSON.parse(trimmed);
        if (typeof obj.ok === 'boolean') return obj;
      } catch { /* try next */ }
    }
    return null;
  }

  /**
   * Main action handler: run-automation
   *
   * @param {object} params
   * @param {string} params.jobId
   * @param {string} params.idempotencyKey  - UUID provided by client
   * @param {string} params.clientStateVersion - client's current state version
   * @param {object} params.session - authenticated session from auth.session()
   * @param {object} params.currentSnapshot - latest known snapshot
   * @returns {Promise<{status, outcome, detail, retryAfterMs?, intentId?, evidenceHash?}>}
   */
  async runAutomation({jobId, idempotencyKey, clientStateVersion, session, currentSnapshot}) {
    const sessionKey = session?.key || 'unknown';

    // Rate limit check
    if (this._isRateLimited(sessionKey)) {
      return {status: 429, outcome: 'RATE_LIMITED', detail: 'Too many action requests. Try again in a minute.'};
    }

    // Double-submit dedup
    const cached = this._checkIdempotency(idempotencyKey);
    if (cached) {
      return {status: 200, outcome: cached.outcome, detail: 'Deduplicated — same idempotency key.', deduplicated: true};
    }

    // Validate jobId type
    if (!jobId || typeof jobId !== 'string' || !/^[0-9a-f-]{36}$/i.test(jobId)) {
      return {status: 400, outcome: 'INVALID_JOB_ID', detail: 'jobId must be a valid UUID.'};
    }

    // Stale page check — clientStateVersion is mandatory; absent = stale
    const serverVersion = this.stateVersion(currentSnapshot);
    if (!clientStateVersion || clientStateVersion !== serverVersion) {
      return {status: 409, outcome: 'STALE_PAGE', detail: 'Client state is stale. Refresh and try again.', serverStateVersion: serverVersion};
    }

    // Target allowlist: job must exist in current snapshot
    const job = this._findJob(jobId, currentSnapshot);
    if (!job) {
      return {status: 422, outcome: 'JOB_NOT_FOUND', detail: 'jobId is not in the current automations allowlist. Refresh and try again.'};
    }

    // Precondition: do not trigger a stuck/running job
    if (job.state === 'UNKNOWN/STUCK') {
      return {status: 409, outcome: 'PRECONDITION_FAILED', detail: 'Job appears stuck. Resolve before triggering.'};
    }

    // Cooldown check
    const cooldownErr = this._checkCooldowns(jobId);
    if (cooldownErr) {
      return {status: 429, outcome: cooldownErr.error, detail: 'Cooldown active.', retryAfterMs: cooldownErr.retryAfterMs};
    }

    // In-flight check (concurrent double-submit guard) — set BEFORE intent write
    if (this._inFlight.has(jobId)) {
      return {status: 409, outcome: 'ALREADY_IN_FLIGHT', detail: 'A trigger for this job is already in progress.'};
    }
    // Mark in-flight immediately so concurrent requests see it during intent write
    this._inFlight.add(jobId);

    // --- INTENT PERSISTENCE (before execution) ---
    const intentId = randomToken(16);
    const intentRecord = {
      intentId,
      jobId,
      jobName: job.name || job.id,
      requestedAt: new Date().toISOString(),
      requestingSessionKey: sha(sessionKey), // store hash, not raw key
      idempotencyKey: idempotencyKey || null,
      status: 'PENDING',
    };

    try {
      this.store.addTimeline({
        id: intentId,
        type: 'RUN_AUTOMATION_INTENT',
        summary: `Run automation intent: ${intentRecord.jobName} (${jobId})`,
        source: 'cockpit-action',
        severity: 'info',
        evidence: intentRecord,
      });
    } catch (persistErr) {
      // If we can't persist intent, abort — clear in-flight and do not proceed
      this._inFlight.delete(jobId);
      return {status: 503, outcome: 'PERSISTENCE_UNAVAILABLE', detail: 'Could not persist intent record. Action aborted.'};
    }

    // Record cooldowns immediately after intent is written (before execution)
    const now = Date.now();
    this._cooldownJob.set(jobId, now);
    this._cooldownGlobal = now;

    // --- EXECUTION ---
    let execResult;
    try {
      execResult = await this._spawnRun(jobId);
    } finally {
      this._inFlight.delete(jobId);
    }

    // Parse output
    const parsed = this._parseRunOutput(execResult.stdout);

    let outcome;
    let terminalSeverity;
    let evidencePayload;

    if (execResult.timedOut) {
      outcome = 'OUTCOME_UNKNOWN';
      terminalSeverity = 'warn';
      evidencePayload = {intentId, jobId, reason: 'timeout', stdout: execResult.stdout?.slice(0, 512), stderr: execResult.stderr?.slice(0, 512)};
    } else if (execResult.spawnError) {
      outcome = 'FAILED';
      terminalSeverity = 'error';
      evidencePayload = {intentId, jobId, reason: 'spawn_error', stderr: execResult.stderr?.slice(0, 512)};
    } else if (execResult.exitCode !== 0) {
      outcome = 'FAILED';
      terminalSeverity = 'error';
      evidencePayload = {intentId, jobId, exitCode: execResult.exitCode, cliError: parsed?.error?.message || execResult.stderr?.slice(0, 512)};
    } else if (!parsed) {
      // Exit 0 but no parseable output — ambiguous
      outcome = 'OUTCOME_UNKNOWN';
      terminalSeverity = 'warn';
      evidencePayload = {intentId, jobId, reason: 'no_parseable_output', stdout: execResult.stdout?.slice(0, 512)};
    } else if (parsed.ok === true) {
      outcome = 'STARTED';
      terminalSeverity = 'info';
      evidencePayload = {intentId, jobId, cliResponse: parsed};
    } else {
      outcome = 'FAILED';
      terminalSeverity = 'error';
      evidencePayload = {intentId, jobId, cliError: parsed?.error?.message || 'unknown'};
    }

    // --- TERMINAL AUDIT RECORD ---
    const evidenceHash = sha(JSON.stringify(evidencePayload));
    try {
      this.store.addTimeline({
        type: `RUN_AUTOMATION_${outcome}`,
        summary: `Run automation ${outcome}: ${intentRecord.jobName} (${jobId})`,
        source: 'cockpit-action',
        severity: terminalSeverity,
        evidence: {...evidencePayload, evidenceHash},
      });
    } catch { /* non-fatal: best effort audit */ }

    // Record idempotency outcome
    this._recordIdempotency(idempotencyKey, jobId, outcome);

    // --- POST-ACTION VERIFICATION (non-blocking, fire-and-forget) ---
    // Only poll if we think the run started
    if (outcome === 'STARTED') {
      this._scheduleVerification(intentId, jobId, intentRecord.jobName, evidenceHash);
    }

    const httpStatus = outcome === 'STARTED' ? 202
      : outcome === 'OUTCOME_UNKNOWN' ? 202
      : 500;

    return {
      status: httpStatus,
      outcome,
      intentId,
      evidenceHash,
      detail: outcome === 'STARTED'
        ? 'Run triggered. Verifying...'
        : outcome === 'OUTCOME_UNKNOWN'
        ? 'Execution outcome is unknown (timeout or no output). Manual verification required.'
        : 'Run trigger failed.',
    };
  }

  /**
   * Post-action verification: poll automations runs after VERIFY_DELAY_MS.
   * Updates the timeline with verification result.
   */
  _scheduleVerification(intentId, jobId, jobName, intentEvidenceHash) {
    const startedAt = Date.now();
    setTimeout(async () => {
      const runsResult = await this._spawnRuns(jobId);
      if (!runsResult) {
        this._writeVerificationRecord(intentId, jobId, jobName, 'UNVERIFIED', {reason: 'poll_failed'}, intentEvidenceHash);
        return;
      }
      const entries = runsResult.entries || [];
      // Find a run that started after we triggered (startedAt - 5s margin)
      const margin = startedAt - 5_000;
      const found = entries.find(e => (e.runAtMs || 0) >= margin);
      if (found) {
        this._writeVerificationRecord(intentId, jobId, jobName, 'VERIFIED', {runEntry: found}, intentEvidenceHash);
      } else {
        this._writeVerificationRecord(intentId, jobId, jobName, 'UNVERIFIED', {reason: 'no_matching_run_found', entries: entries.slice(0, 3)}, intentEvidenceHash);
      }
    }, VERIFY_DELAY_MS);
  }

  _writeVerificationRecord(intentId, jobId, jobName, verificationStatus, evidence, intentEvidenceHash) {
    try {
      this.store.addTimeline({
        type: `RUN_AUTOMATION_VERIFICATION_${verificationStatus}`,
        summary: `Run automation verification ${verificationStatus}: ${jobName} (${jobId})`,
        source: 'cockpit-action-verify',
        severity: verificationStatus === 'VERIFIED' ? 'info' : 'warn',
        evidence: {intentId, jobId, intentEvidenceHash, ...evidence},
      });
    } catch { /* non-fatal */ }
  }

  /**
   * Check pause-specific cooldowns.
   * Returns null if OK, or {error, retryAfterMs} if blocked.
   */
  _checkPauseCooldowns(jobId) {
    const now = Date.now();
    const globalAge = now - this._pauseCooldownGlobal;
    if (globalAge < PAUSE_COOLDOWN_GLOBAL_MS) {
      return {error: 'COOLDOWN_ACTIVE', retryAfterMs: PAUSE_COOLDOWN_GLOBAL_MS - globalAge};
    }
    const jobAge = now - (this._pauseCooldownJob.get(jobId) || 0);
    if (jobAge < PAUSE_COOLDOWN_JOB_MS) {
      return {error: 'COOLDOWN_ACTIVE', retryAfterMs: PAUSE_COOLDOWN_JOB_MS - jobAge};
    }
    return null;
  }

  /**
   * Execute: openclaw cron disable <jobId> --json
   * Returns {exitCode, stdout, stderr, timedOut}
   */
  async _spawnDisable(jobId) {
    return this._spawnPauseCmd(['cron', 'disable', jobId, '--json']);
  }

  /**
   * Execute: openclaw cron enable <jobId> --json
   * Returns {exitCode, stdout, stderr, timedOut}
   */
  async _spawnEnable(jobId) {
    return this._spawnPauseCmd(['cron', 'enable', jobId, '--json']);
  }

  /**
   * Execute: openclaw cron get <jobId> --json
   * Returns parsed JSON or null on failure.
   */
  async _spawnGet(jobId) {
    return new Promise(resolve => {
      let stdout = '';
      const child = spawn('openclaw', ['cron', 'get', jobId, '--json'], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
        resolve(null);
      }, EXEC_TIMEOUT_MS);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.on('close', exitCode => {
        clearTimeout(timer);
        if (exitCode !== 0) { resolve(null); return; }
        try { resolve(JSON.parse(stdout)); } catch { resolve(null); }
      });
      child.on('error', () => { clearTimeout(timer); resolve(null); });
    });
  }

  /**
   * Generic spawn helper for pause/resume CLI calls.
   * Returns {exitCode, stdout, stderr, timedOut}
   */
  async _spawnPauseCmd(args) {
    return new Promise(resolve => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      const child = spawn('openclaw', args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        timedOut = true;
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
      }, EXEC_TIMEOUT_MS);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.stderr.on('data', d => { stderr += d.toString('utf8'); });
      child.on('close', exitCode => {
        clearTimeout(timer);
        resolve({exitCode: exitCode ?? -1, stdout, stderr, timedOut});
      });
      child.on('error', err => {
        clearTimeout(timer);
        resolve({exitCode: -1, stdout, stderr: stderr + err.message, timedOut: false, spawnError: true});
      });
    });
  }

  /**
   * Parse the CLI stdout for a disable/enable call.
   * Returns {parsed, ok} or null if unparseable.
   * The CLI may return {ok:true} or just exit 0 with a description.
   * We also accept exit 0 with non-JSON output as success (CLI quirk).
   */
  _parsePauseOutput(stdout) {
    if (!stdout || !stdout.trim()) return null;
    for (const line of stdout.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('{')) continue;
      try {
        const obj = JSON.parse(trimmed);
        // Accept any object with ok:true, or {enabled:...}
        if (typeof obj.ok === 'boolean' || typeof obj.enabled === 'boolean') return obj;
      } catch { /* try next */ }
    }
    // No JSON found but stdout is non-empty — treat as success (CLI may print plain text)
    return {ok: true, rawOutput: stdout.trim().slice(0, 200)};
  }

  /**
   * Main action handler: pause-automation
   *
   * @param {object} params
   * @param {string} params.jobId
   * @param {boolean} params.pause  true = disable scheduling, false = re-enable
   * @param {string} params.idempotencyKey  - UUID provided by client
   * @param {string} params.clientStateVersion - client's current state version
   * @param {object} params.session - authenticated session
   * @param {object} params.currentSnapshot - latest known snapshot
   * @returns {Promise<{status, outcome, detail, retryAfterMs?, intentId?, evidenceHash?}>}
   */
  async pauseAutomation({jobId, pause, idempotencyKey, clientStateVersion, session, currentSnapshot}) {
    const sessionKey = session?.key || 'unknown';
    const intentType = pause ? 'INTENT_PAUSE' : 'INTENT_RESUME';
    const successOutcome = pause ? 'PAUSED' : 'RESUMED';
    const failedOutcome = pause ? 'PAUSE_FAILED' : 'RESUME_FAILED';
    const cliAction = pause ? 'disable' : 'enable';

    // Rate limit check (shared pool with run-automation to prevent combined abuse)
    if (this._isRateLimited(sessionKey)) {
      return {status: 429, outcome: 'RATE_LIMITED', detail: 'Too many action requests. Try again in a minute.'};
    }

    // Double-submit dedup
    const cached = this._checkIdempotency(idempotencyKey);
    if (cached) {
      return {status: 200, outcome: cached.outcome, detail: 'Deduplicated — same idempotency key.', deduplicated: true};
    }

    // Validate jobId type
    if (!jobId || typeof jobId !== 'string' || !/^[0-9a-f-]{36}$/i.test(jobId)) {
      return {status: 400, outcome: 'INVALID_JOB_ID', detail: 'jobId must be a valid UUID.'};
    }

    // Validate pause flag
    if (typeof pause !== 'boolean') {
      return {status: 400, outcome: 'INVALID_PAUSE_FLAG', detail: 'pause must be a boolean.'};
    }

    // Stale page check — clientStateVersion is mandatory
    const serverVersion = this.stateVersion(currentSnapshot);
    if (!clientStateVersion || clientStateVersion !== serverVersion) {
      return {status: 409, outcome: 'STALE_PAGE', detail: 'Client state is stale. Refresh and try again.', serverStateVersion: serverVersion};
    }

    // Target allowlist: job must exist in current snapshot
    const job = this._findJob(jobId, currentSnapshot);
    if (!job) {
      return {status: 422, outcome: 'JOB_NOT_FOUND', detail: 'jobId is not in the current automations allowlist. Refresh and try again.'};
    }

    // Pause-specific cooldown check (lower than run)
    const cooldownErr = this._checkPauseCooldowns(jobId);
    if (cooldownErr) {
      return {status: 429, outcome: cooldownErr.error, detail: 'Cooldown active.', retryAfterMs: cooldownErr.retryAfterMs};
    }

    // In-flight check — set BEFORE intent write
    if (this._pauseInFlight.has(jobId)) {
      return {status: 409, outcome: 'ALREADY_IN_FLIGHT', detail: 'A pause/resume action for this job is already in progress.'};
    }
    this._pauseInFlight.add(jobId);

    // --- INTENT PERSISTENCE (before execution) ---
    const intentId = randomToken(16);
    const intentRecord = {
      intentId,
      jobId,
      jobName: job.name || job.id,
      action: cliAction,
      pause,
      requestedAt: new Date().toISOString(),
      requestingSessionKey: sha(sessionKey),
      idempotencyKey: idempotencyKey || null,
      status: 'PENDING',
    };

    try {
      this.store.addTimeline({
        id: intentId,
        type: intentType,
        summary: `${pause ? 'Pause' : 'Resume'} automation intent: ${intentRecord.jobName} (${jobId})`,
        source: 'cockpit-action',
        severity: 'info',
        evidence: intentRecord,
      });
    } catch (persistErr) {
      this._pauseInFlight.delete(jobId);
      return {status: 503, outcome: 'PERSISTENCE_UNAVAILABLE', detail: 'Could not persist intent record. Action aborted.'};
    }

    // Record cooldowns immediately after intent is written
    const now = Date.now();
    this._pauseCooldownJob.set(jobId, now);
    this._pauseCooldownGlobal = now;

    // --- EXECUTION ---
    let execResult;
    try {
      execResult = pause ? await this._spawnDisable(jobId) : await this._spawnEnable(jobId);
    } finally {
      this._pauseInFlight.delete(jobId);
    }

    // Parse output
    const parsed = this._parsePauseOutput(execResult.stdout);

    let outcome;
    let terminalSeverity;
    let evidencePayload;

    if (execResult.timedOut) {
      outcome = 'OUTCOME_UNKNOWN';
      terminalSeverity = 'warn';
      evidencePayload = {intentId, jobId, reason: 'timeout', stdout: execResult.stdout?.slice(0, 512), stderr: execResult.stderr?.slice(0, 512)};
    } else if (execResult.spawnError) {
      outcome = failedOutcome;
      terminalSeverity = 'error';
      evidencePayload = {intentId, jobId, reason: 'spawn_error', stderr: execResult.stderr?.slice(0, 512)};
    } else if (execResult.exitCode !== 0) {
      outcome = failedOutcome;
      terminalSeverity = 'error';
      evidencePayload = {intentId, jobId, exitCode: execResult.exitCode, cliError: parsed?.error?.message || execResult.stderr?.slice(0, 512)};
    } else if (parsed && (parsed.ok === true || typeof parsed.enabled === 'boolean' || parsed.rawOutput)) {
      outcome = successOutcome;
      terminalSeverity = 'info';
      evidencePayload = {intentId, jobId, cliResponse: parsed};
    } else if (!parsed) {
      // Exit 0 but no parseable / recognisable output — ambiguous
      outcome = 'OUTCOME_UNKNOWN';
      terminalSeverity = 'warn';
      evidencePayload = {intentId, jobId, reason: 'no_parseable_output', stdout: execResult.stdout?.slice(0, 512)};
    } else {
      outcome = failedOutcome;
      terminalSeverity = 'error';
      evidencePayload = {intentId, jobId, cliError: parsed?.error?.message || 'unknown'};
    }

    // --- TERMINAL AUDIT RECORD ---
    const evidenceHash = sha(JSON.stringify(evidencePayload));
    try {
      this.store.addTimeline({
        type: outcome,
        summary: `${pause ? 'Pause' : 'Resume'} automation ${outcome}: ${intentRecord.jobName} (${jobId})`,
        source: 'cockpit-action',
        severity: terminalSeverity,
        evidence: {...evidencePayload, evidenceHash},
      });
    } catch { /* non-fatal: best effort audit */ }

    // Record idempotency outcome
    this._recordIdempotency(idempotencyKey, jobId, outcome);

    // --- POST-ACTION VERIFICATION (non-blocking, fire-and-forget) ---
    if (outcome === successOutcome) {
      this._schedulePauseVerification(intentId, jobId, intentRecord.jobName, evidenceHash, pause);
    }

    const httpStatus = outcome === successOutcome ? 200
      : outcome === 'OUTCOME_UNKNOWN' ? 202
      : 500;

    return {
      status: httpStatus,
      outcome,
      intentId,
      evidenceHash,
      detail: outcome === successOutcome
        ? `${pause ? 'Paused' : 'Resumed'} successfully. Verifying state…`
        : outcome === 'OUTCOME_UNKNOWN'
        ? 'Execution outcome is unknown (timeout or no output). Manual verification required.'
        : `${pause ? 'Pause' : 'Resume'} failed.`,
    };
  }

  /**
   * Post-action verification for pause/resume:
   * Poll cron get after VERIFY_DELAY_MS and confirm enabled state changed.
   */
  _schedulePauseVerification(intentId, jobId, jobName, intentEvidenceHash, expectedPaused) {
    setTimeout(async () => {
      const getResult = await this._spawnGet(jobId);
      if (!getResult) {
        this._writePauseVerificationRecord(intentId, jobId, jobName, 'UNVERIFIED', {reason: 'poll_failed'}, intentEvidenceHash);
        return;
      }
      // CLI returns the job record; enabled field confirms state
      const enabledField = getResult.enabled;
      const stateCorrect = typeof enabledField === 'boolean'
        ? (expectedPaused ? !enabledField : enabledField)
        : null;
      if (stateCorrect === true) {
        this._writePauseVerificationRecord(intentId, jobId, jobName, 'VERIFIED', {enabledField, expectedPaused}, intentEvidenceHash);
      } else {
        this._writePauseVerificationRecord(intentId, jobId, jobName, 'UNVERIFIED', {reason: stateCorrect === false ? 'state_mismatch' : 'no_enabled_field', getResult}, intentEvidenceHash);
      }
    }, VERIFY_DELAY_MS);
  }

  _writePauseVerificationRecord(intentId, jobId, jobName, verificationStatus, evidence, intentEvidenceHash) {
    try {
      this.store.addTimeline({
        type: `PAUSE_AUTOMATION_VERIFICATION_${verificationStatus}`,
        summary: `Pause automation verification ${verificationStatus}: ${jobName} (${jobId})`,
        source: 'cockpit-action-verify',
        severity: verificationStatus === 'VERIFIED' ? 'info' : 'warn',
        evidence: {intentId, jobId, intentEvidenceHash, ...evidence},
      });
    } catch { /* non-fatal */ }
  }

  /**
   * Expose constants for tests
   */
  static get COOLDOWN_JOB_MS() { return COOLDOWN_JOB_MS; }
  static get COOLDOWN_GLOBAL_MS() { return COOLDOWN_GLOBAL_MS; }
  static get PAUSE_COOLDOWN_JOB_MS() { return PAUSE_COOLDOWN_JOB_MS; }
  static get PAUSE_COOLDOWN_GLOBAL_MS() { return PAUSE_COOLDOWN_GLOBAL_MS; }
  static get RATE_LIMIT_MAX() { return RATE_LIMIT_MAX; }
  static get RATE_LIMIT_WINDOW_MS() { return RATE_LIMIT_WINDOW_MS; }
  static get EXEC_TIMEOUT_MS() { return EXEC_TIMEOUT_MS; }
  static get VERIFY_DELAY_MS() { return VERIFY_DELAY_MS; }
  static get IDEMPOTENCY_WINDOW_MS() { return IDEMPOTENCY_WINDOW_MS; }

  // ─── RESTART GATEWAY ─────────────────────────────────────────────────────

  /**
   * Execute: openclaw gateway stability --json
   * Returns parsed JSON or null on failure.
   */
  async _spawnGatewayStability() {
    return new Promise(resolve => {
      let stdout = '';
      const child = spawn('openclaw', ['gateway', 'stability', '--json'], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
        resolve(null);
      }, 15_000);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.on('close', exitCode => {
        clearTimeout(timer);
        if (exitCode !== 0) { resolve(null); return; }
        try { resolve(JSON.parse(stdout)); } catch { resolve(null); }
      });
      child.on('error', () => { clearTimeout(timer); resolve(null); });
    });
  }

  /**
   * Execute: openclaw gateway status --no-probe --json
   * Returns parsed JSON or null on failure.
   */
  async _spawnGatewayStatus() {
    return new Promise(resolve => {
      let stdout = '';
      const child = spawn('openclaw', ['gateway', 'status', '--no-probe', '--json'], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
        resolve(null);
      }, 15_000);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.on('close', exitCode => {
        clearTimeout(timer);
        if (exitCode !== 0) { resolve(null); return; }
        try { resolve(JSON.parse(stdout)); } catch { resolve(null); }
      });
      child.on('error', () => { clearTimeout(timer); resolve(null); });
    });
  }

  /**
   * Execute: sc.exe query OpenClawGateway
   * Returns 'RUNNING' | 'NOT_RUNNING' | 'UNKNOWN'
   */
  async _spawnScQuery() {
    return new Promise(resolve => {
      let stdout = '';
      const child = spawn('sc.exe', ['query', 'OpenClawGateway'], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
        resolve('UNKNOWN');
      }, 10_000);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.on('close', () => {
        clearTimeout(timer);
        if (/STATE\s*:\s*\d+\s+RUNNING/i.test(stdout)) resolve('RUNNING');
        else if (/STATE\s*:/i.test(stdout)) resolve('NOT_RUNNING');
        else resolve('UNKNOWN');
      });
      child.on('error', () => { clearTimeout(timer); resolve('UNKNOWN'); });
    });
  }

  /**
   * Execute: openclaw gateway restart --safe --json
   * Returns {exitCode, stdout, stderr, timedOut}
   * NOTE: --force is NEVER passed. Only --safe is exposed.
   */
  async _spawnGatewayRestart() {
    return new Promise(resolve => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      // Hard assertion: args are compile-time fixed, no jobId or user input injected.
      const args = ['gateway', 'restart', '--safe', '--json'];
      const child = spawn('openclaw', args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        timedOut = true;
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
      }, RESTART_TIMEOUT_MS);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.stderr.on('data', d => { stderr += d.toString('utf8'); });
      child.on('close', exitCode => {
        clearTimeout(timer);
        resolve({exitCode: exitCode ?? -1, stdout, stderr, timedOut});
      });
      child.on('error', err => {
        clearTimeout(timer);
        resolve({exitCode: -1, stdout, stderr: stderr + err.message, timedOut: false, spawnError: true});
      });
    });
  }

  /**
   * Poll gateway health until ok:true or timeout (60s, 3s interval).
   * Returns {ok, reconnectedInMs, timedOut}
   */
  async _pollGatewayHealth() {
    const start = Date.now();
    const POLL_TIMEOUT = 60_000;
    const POLL_INTERVAL = 3_000;
    while (Date.now() - start < POLL_TIMEOUT) {
      await new Promise(r => setTimeout(r, POLL_INTERVAL));
      const result = await this._spawnGatewayHealth();
      if (result && result.ok === true) {
        return {ok: true, reconnectedInMs: Date.now() - start};
      }
    }
    return {ok: false, timedOut: true};
  }

  /**
   * Execute: openclaw gateway health --json
   * Returns parsed JSON or null on failure.
   */
  async _spawnGatewayHealth() {
    return new Promise(resolve => {
      let stdout = '';
      const child = spawn('openclaw', ['gateway', 'health', '--json'], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
        resolve(null);
      }, 10_000);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.on('close', exitCode => {
        clearTimeout(timer);
        if (exitCode !== 0) { resolve(null); return; }
        try { resolve(JSON.parse(stdout)); } catch { resolve(null); }
      });
      child.on('error', () => { clearTimeout(timer); resolve(null); });
    });
  }

  /**
   * Execute: openclaw channels status --json
   * Returns parsed JSON or null on failure.
   */
  async _spawnChannelsStatus() {
    return new Promise(resolve => {
      let stdout = '';
      const child = spawn('openclaw', ['channels', 'status', '--json'], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
        resolve(null);
      }, 10_000);
      child.stdout.on('data', d => { stdout += d.toString('utf8'); });
      child.on('close', exitCode => {
        clearTimeout(timer);
        if (exitCode !== 0) { resolve(null); return; }
        try { resolve(JSON.parse(stdout)); } catch { resolve(null); }
      });
      child.on('error', () => { clearTimeout(timer); resolve(null); });
    });
  }

  /**
   * Main action handler: restart-gateway
   *
   * @param {object} params
   * @param {string} params.idempotencyKey  - UUID provided by client
   * @param {string} params.clientStateVersion - client's current state version
   * @param {object} params.session - authenticated session
   * @param {object} params.currentSnapshot - latest known snapshot
   * @returns {Promise<{status, outcome, detail, retryAfterMs?, intentId?, evidenceHash?, activeRuns?}>}
   */
  async restartGateway({idempotencyKey, clientStateVersion, session, currentSnapshot}) {
    const sessionKey = session?.key || 'unknown';

    // Rate limit check (shared pool)
    if (this._isRateLimited(sessionKey)) {
      return {status: 429, outcome: 'RATE_LIMITED', detail: 'Too many action requests. Try again in a minute.'};
    }

    // Double-submit dedup
    const cached = this._checkIdempotency(idempotencyKey);
    if (cached) {
      return {status: 200, outcome: cached.outcome, detail: 'Deduplicated — same idempotency key.', deduplicated: true};
    }

    // Stale page check — clientStateVersion is mandatory
    const serverVersion = this.stateVersion(currentSnapshot);
    if (!clientStateVersion || clientStateVersion !== serverVersion) {
      return {status: 409, outcome: 'STALE_PAGE', detail: 'Client state is stale. Refresh and try again.', serverStateVersion: serverVersion};
    }

    // Cooldown check (300s — restart is high-impact)
    const cooldownErr = this._checkRestartCooldown();
    if (cooldownErr) {
      return {status: 429, outcome: cooldownErr.error, detail: 'Restart cooldown active.', retryAfterMs: cooldownErr.retryAfterMs};
    }

    // In-flight guard
    if (this._restartInFlight) {
      return {status: 409, outcome: 'ALREADY_IN_FLIGHT', detail: 'A gateway restart is already in progress.'};
    }
    this._restartInFlight = true;

    // --- NSSM SERVICE PRE-CHECK ---
    let nssmState;
    try {
      nssmState = await this._spawnScQuery();
    } catch {
      nssmState = 'UNKNOWN';
    }
    if (nssmState !== 'RUNNING') {
      this._restartInFlight = false;
      return {
        status: 409,
        outcome: 'PRECONDITION_FAILED',
        reason: 'supervisor_not_running',
        detail: `OpenClawGateway service is not RUNNING (state: ${nssmState}). Cannot restart.`,
      };
    }

    // --- ACTIVE WORK PRE-CHECK (informational only — --safe handles drain) ---
    let activeRuns = 0;
    try {
      const stability = await this._spawnGatewayStability();
      if (stability && stability.summary) {
        const s = stability.summary;
        activeRuns = (Number(s.active || 0)) + (Number(s.waiting || 0)) + (Number(s.queued || 0));
        if (!Number.isFinite(activeRuns)) activeRuns = 0;
      }
    } catch { /* non-fatal — proceed */ }

    // --- INTENT PERSISTENCE (before execution) ---
    const intentId = randomToken(16);
    const intentRecord = {
      intentId,
      action: 'restart-gateway',
      activeRuns,
      nssmState,
      requestedAt: new Date().toISOString(),
      requestingSessionKey: sha(sessionKey),
      idempotencyKey: idempotencyKey || null,
      status: 'PENDING',
    };

    try {
      this.store.addTimeline({
        id: intentId,
        type: 'INTENT_RESTART_GATEWAY',
        summary: `Gateway restart intent (activeRuns: ${activeRuns})`,
        source: 'cockpit-action',
        severity: 'warn',
        evidence: intentRecord,
      });
    } catch (persistErr) {
      this._restartInFlight = false;
      return {status: 503, outcome: 'PERSISTENCE_UNAVAILABLE', detail: 'Could not persist intent record. Action aborted.'};
    }

    // Record cooldown immediately after intent is written
    this._restartCooldownAt = Date.now();

    // --- EXECUTION ---
    let execResult;
    try {
      execResult = await this._spawnGatewayRestart();
    } finally {
      this._restartInFlight = false;
    }

    // Parse output
    let parsed = null;
    if (execResult.stdout && execResult.stdout.trim()) {
      for (const line of execResult.stdout.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('{')) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (typeof obj.ok === 'boolean') { parsed = obj; break; }
        } catch { /* try next */ }
      }
    }

    let outcome;
    let terminalSeverity;
    let evidencePayload;

    if (execResult.timedOut) {
      outcome = 'OUTCOME_UNKNOWN';
      terminalSeverity = 'warn';
      evidencePayload = {intentId, reason: 'timeout', stdout: execResult.stdout?.slice(0, 512), stderr: execResult.stderr?.slice(0, 512), activeRuns};
    } else if (execResult.spawnError) {
      outcome = 'RESTART_FAILED';
      terminalSeverity = 'error';
      evidencePayload = {intentId, reason: 'spawn_error', stderr: execResult.stderr?.slice(0, 512), activeRuns};
    } else if (execResult.exitCode !== 0) {
      outcome = 'RESTART_FAILED';
      terminalSeverity = 'error';
      evidencePayload = {intentId, exitCode: execResult.exitCode, cliError: parsed?.error?.message || execResult.stderr?.slice(0, 512), activeRuns};
    } else if (parsed && parsed.ok === true) {
      outcome = 'RESTARTED';
      terminalSeverity = 'info';
      evidencePayload = {intentId, cliResponse: parsed, activeRuns};
    } else {
      // Exit 0 but no clear ok:true — ambiguous
      outcome = 'OUTCOME_UNKNOWN';
      terminalSeverity = 'warn';
      evidencePayload = {intentId, reason: 'no_ok_true_in_output', stdout: execResult.stdout?.slice(0, 512), activeRuns};
    }

    // --- TERMINAL AUDIT RECORD ---
    const evidenceHash = sha(JSON.stringify(evidencePayload));
    try {
      this.store.addTimeline({
        type: `${outcome}`,
        summary: `Gateway restart ${outcome} (activeRuns: ${activeRuns})`,
        source: 'cockpit-action',
        severity: terminalSeverity,
        evidence: {...evidencePayload, evidenceHash},
      });
    } catch { /* non-fatal: best effort audit */ }

    // Record idempotency outcome
    this._recordIdempotency(idempotencyKey, '_gateway_', outcome);

    // --- POST-RESTART VERIFICATION (non-blocking, fire-and-forget) ---
    if (outcome === 'RESTARTED') {
      this._scheduleRestartVerification(intentId, evidenceHash);
    }

    const httpStatus = outcome === 'RESTARTED' ? 202
      : outcome === 'OUTCOME_UNKNOWN' ? 202
      : 500;

    return {
      status: httpStatus,
      outcome,
      intentId,
      evidenceHash,
      activeRuns,
      detail: outcome === 'RESTARTED'
        ? 'Gateway restarting. Polling for reconnect…'
        : outcome === 'OUTCOME_UNKNOWN'
        ? 'Execution outcome is unknown (timeout or ambiguous output). Check Gateway manually.'
        : 'Gateway restart failed.',
    };
  }

  /**
   * Check restart-specific cooldown (300s global).
   * Returns null if OK, or {error, retryAfterMs} if blocked.
   */
  _checkRestartCooldown() {
    if (!this._restartCooldownAt) return null;
    const age = Date.now() - this._restartCooldownAt;
    if (age < RESTART_COOLDOWN_MS) {
      return {error: 'COOLDOWN_ACTIVE', retryAfterMs: RESTART_COOLDOWN_MS - age};
    }
    return null;
  }

  /**
   * Post-restart verification: poll gateway health until ok:true or 60s timeout.
   * Then write RESTART_VERIFIED or RESTART_UNVERIFIED.
   */
  _scheduleRestartVerification(intentId, intentEvidenceHash) {
    // Fire-and-forget — runs after the response is sent
    (async () => {
      const pollResult = await this._pollGatewayHealth();
      const verStatus = pollResult.ok ? 'RESTART_VERIFIED' : 'RESTART_UNVERIFIED';
      const severity = pollResult.ok ? 'info' : 'warn';
      try {
        this.store.addTimeline({
          type: verStatus,
          summary: pollResult.ok
            ? `Gateway restart verified — reconnected in ${pollResult.reconnectedInMs}ms`
            : 'Gateway restart unverified — health poll timed out (60s)',
          source: 'cockpit-action-verify',
          severity,
          evidence: {intentId, intentEvidenceHash, ...pollResult},
        });
      } catch { /* non-fatal */ }
    })();
  }

  // expose restart constants for tests
  static get RESTART_COOLDOWN_MS() { return RESTART_COOLDOWN_MS; }
  static get RESTART_TIMEOUT_MS() { return RESTART_TIMEOUT_MS; }
}
