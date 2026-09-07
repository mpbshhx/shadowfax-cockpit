// State
let csrf = '', stateVersion = null, mode = 'login'; // stateVersion=null until first /api/state loaded
// Per-job cooldown tracking: jobId -> cooldown expiry timestamp
const jobCooldowns = new Map();
// Track in-flight run requests: jobId -> true
const jobInFlight = new Set();
// Per-job pause cooldown tracking: jobId -> cooldown expiry timestamp
const pauseCooldowns = new Map();
// Track in-flight pause/resume requests: jobId -> true
const pauseInFlight = new Set();
// Live enabled state from SSE snapshot: jobId -> boolean
const jobEnabledState = new Map();
// Restart Gateway state
let restartCooldownExpiry = 0;      // ms timestamp when 5-min cooldown clears
let restartInFlight = false;         // true while restart is running
let gatewayReconnecting = false;     // true during post-restart reconnect polling

const $ = x => document.querySelector(x);
const esc = x => String(x ?? 'unknown').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cls = x => esc(x).replaceAll(' ', '-');

function metric(k, v) {
  return `<div class="metric"><small>${esc(k)}</small><b class="${cls(v)}">${esc(v)}</b></div>`;
}
function kv(k, v) {
  return `<div class="kv"><span class="muted">${esc(k)}</span><b class="${cls(v)}">${esc(v)}</b></div>`;
}

// Generate a UUID v4 for idempotency keys
function uuidv4() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16));
}

// Returns ms remaining on a job's cooldown, 0 if clear
function cooldownRemaining(jobId) {
  const exp = jobCooldowns.get(jobId) || 0;
  return Math.max(0, exp - Date.now());
}

// Returns ms remaining on a job's pause cooldown, 0 if clear
function pauseCooldownRemaining(jobId) {
  const exp = pauseCooldowns.get(jobId) || 0;
  return Math.max(0, exp - Date.now());
}

async function bootstrap() {
  const b = await fetch('/api/bootstrap').then(r => r.json());
  mode = b.enrollmentRequired ? 'enroll' : 'login';
  $('#authTitle').textContent = b.enrollmentRequired ? 'Enrollment required' : 'Operator sign in';
  $('#authHint').textContent = b.enrollmentRequired ? 'Read the protected auth/bootstrap.token file locally. The token never appears here.' : '';
  $('#tokenLabel').hidden = !b.enrollmentRequired;
  await load();
}

async function load() {
  const r = await fetch('/api/state');
  if (r.status === 401) { $('#auth').hidden = false; $('#cockpit').hidden = true; return; }
  const x = await r.json();
  csrf = x.csrf;
  stateVersion = x.stateVersion || '';
  $('#auth').hidden = true;
  $('#cockpit').hidden = false;
  $('#logout').hidden = false;
  render(x);
}

function renderAutomations(jobs) {
  if (!jobs || !jobs.length) return '<p class="muted">No trustworthy automation snapshot.</p>';
  const rows = jobs.map(j => {
    const id = j.id;
    const name = esc(j.name || j.id);
    const isStale = stateVersion === null || stateVersion === '';

    // Run button
    const cdLeft = cooldownRemaining(id);
    const inFlight = jobInFlight.has(id);
    const stuck = j.state === 'UNKNOWN/STUCK';
    const runDisabled = isStale || cdLeft > 0 || inFlight || stuck;
    let runLabel, runTitle;
    if (inFlight) { runLabel = '⏳ Running…'; runTitle = 'Trigger in progress'; }
    else if (cdLeft > 0) { runLabel = `Wait ${Math.ceil(cdLeft/1000)}s`; runTitle = 'Cooldown active'; }
    else if (stuck) { runLabel = 'STUCK'; runTitle = 'Job appears stuck — resolve before triggering'; }
    else if (isStale) { runLabel = 'Refresh'; runTitle = 'Page state stale — reload'; }
    else { runLabel = '▶ Run now'; runTitle = 'Manually trigger this automation'; }

    // Pause/resume button — reflect live enabled state from SSE snapshot
    // jobEnabledState tracks most recent snapshot value; fall back to j.enabled
    const isEnabled = jobEnabledState.has(id) ? jobEnabledState.get(id) : j.enabled;
    const pauseCdLeft = pauseCooldownRemaining(id);
    const pauseInflight = pauseInFlight.has(id);
    const pauseDisabled = isStale || pauseCdLeft > 0 || pauseInflight;
    let pauseLabel, pauseTitle;
    if (pauseInflight) { pauseLabel = '⏳ …'; pauseTitle = 'Pause/resume in progress'; }
    else if (pauseCdLeft > 0) { pauseLabel = `Wait ${Math.ceil(pauseCdLeft/1000)}s`; pauseTitle = 'Cooldown active'; }
    else if (isStale) { pauseLabel = 'Refresh'; pauseTitle = 'Page state stale — reload'; }
    else if (isEnabled) { pauseLabel = '⏸ Pause'; pauseTitle = 'Pause scheduling for this job'; }
    else { pauseLabel = '▶ Resume'; pauseTitle = 'Resume scheduling for this job'; }

    return `<tr>
      <td>${name}</td>
      <td>${esc(j.enabled)}</td>
      <td class="${cls(j.state)}">${esc(j.state)}</td>
      <td>${esc(j.deliveryState)}</td>
      <td>${esc(j.consecutiveErrors || 0)}</td>
      <td style="display:flex;gap:6px;flex-wrap:wrap">
        <button class="run-btn${runDisabled?' btn-disabled':''}" data-jobid="${esc(id)}" data-jobname="${name}" ${runDisabled?'disabled':''} title="${esc(runTitle)}">${runLabel}</button>
        <button class="pause-btn${pauseDisabled?' btn-disabled':''}" data-jobid="${esc(id)}" data-jobname="${name}" data-enabled="${isEnabled}" ${pauseDisabled?'disabled':''} title="${esc(pauseTitle)}">${pauseLabel}</button>
      </td>
    </tr>`;
  }).join('');
  return `<table><thead><tr><th>Name</th><th>Enabled</th><th>State</th><th>Delivery</th><th>Errors</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function render(x) {
  const s = x.snapshot, g = s.gateway, v = s.visibility, w = s.work,
        a = s.automations || [], st = s.storage, p = s.persistence;
  // Update live enabled state map from SSE snapshot
  for (const j of a) {
    jobEnabledState.set(j.id, !!j.enabled);
  }
  $('#strip').innerHTML = [
    ['Gateway', g.state], ['Visibility', v.state], ['Disk', st.state],
    ['Active runs', w.active ?? 'UNKNOWN'], ['Persistence', p.state],
    ['Unacked', Object.keys(x.acknowledgements || {}).length]
  ].map(z => metric(...z)).join('');
  // Gateway tile
  let gatewayHtml = kv('State', g.state) + kv('Runtime', g.version) + kv('Compatibility', g.runtime) + kv('Evidence', g.evidenceAt);
  if (gatewayReconnecting) {
    gatewayHtml += '<p class="restart-reconnecting">\u21ba Gateway reconnecting…</p>';
  }
  $('#gateway').innerHTML = gatewayHtml;
  // Render restart button in Gateway tile
  renderRestartButton();
  $('#visibility').innerHTML = kv('State', v.state) + kv('Age ms', v.ageMs) + kv('Partial', v.partial) + kv('Failures', v.failures);
  $('#work').innerHTML = kv('State', w.state) + kv('Active', w.active) + kv('Oldest age ms', w.oldestAgeMs) + Object.entries(w.byStatus || {}).map(z => kv(...z)).join('');
  $('#automations').innerHTML = renderAutomations(a);
  $('#storage').innerHTML = kv('State', st.state) + kv('Free bytes', st.freeBytes) + kv('Total bytes', st.totalBytes) + kv('Observed', st.observedAt);
  $('#persistence').innerHTML = kv('State', p.state) + kv('Integrity', p.integrity) + kv('Write failures', p.writeFailures);
  $('#timeline').innerHTML = (x.timeline || []).map(e =>
    `<div class="event ${cls(e.severity||'info')}"><b>${esc(e.type)}</b> ${esc(e.summary)}<br><small>${esc(e.occurredAt)} · ${esc(e.source)} · evidence ${esc(e.evidenceHash)}</small></div>`
  ).join('') || '<p class="muted">No retained transitions.</p>';

  // Wire up run buttons
  document.querySelectorAll('.run-btn:not([disabled])').forEach(btn => {
    btn.onclick = () => confirmRun(btn.dataset.jobid, btn.dataset.jobname);
  });

  // Wire up pause/resume buttons
  document.querySelectorAll('.pause-btn:not([disabled])').forEach(btn => {
    btn.onclick = () => {
      const isEnabled = btn.dataset.enabled === 'true';
      confirmPause(btn.dataset.jobid, btn.dataset.jobname, isEnabled);
    };
  });

  // If any cooldown is active, schedule a re-render to refresh countdown
  const allExpiries = [
    ...[...jobCooldowns.values()],
    ...[...pauseCooldowns.values()],
    ...(restartCooldownExpiry > Date.now() ? [restartCooldownExpiry] : []),
  ].filter(e => e > Date.now());
  if (allExpiries.length > 0) {
    setTimeout(() => load(), 1000);
  }
  // When gateway comes back after restart, clear reconnecting state
  if (gatewayReconnecting && g.state === 'HEALTHY') {
    gatewayReconnecting = false;
    renderRestartButton();
  }
}

function confirmPause(jobId, jobName, currentlyEnabled) {
  // currentlyEnabled: true = job is running, action is Pause
  //                   false = job is paused, action is Resume
  const action = currentlyEnabled ? 'Pause' : 'Resume';
  $('#pauseDialogTitle').textContent = `${action} scheduling`;
  $('#pauseDialogDesc').innerHTML = `${action} scheduling for <b>${esc(jobName)}</b>?`;
  $('#pauseJobName').textContent = jobName;
  $('#pauseJobId').textContent = jobId;
  $('#pauseConfirmDialog').dataset.jobid = jobId;
  $('#pauseConfirmDialog').dataset.jobname = jobName;
  $('#pauseConfirmDialog').dataset.pause = currentlyEnabled ? 'true' : 'false';
  $('#pauseOutcome').hidden = true;
  $('#pauseOutcome').className = '';
  $('#pauseOutcome').textContent = '';
  $('#confirmPauseBtn').disabled = false;
  $('#confirmPauseBtn').textContent = currentlyEnabled ? '⏸ Pause' : '▶ Resume';
  $('#pauseConfirmDialog').showModal();
}

async function executePause(jobId, jobName, pause) {
  const idempotencyKey = uuidv4();
  $('#confirmPauseBtn').disabled = true;
  $('#confirmPauseBtn').textContent = '⏳ …';
  $('#pauseOutcome').hidden = false;
  $('#pauseOutcome').className = 'outcome-pending';
  $('#pauseOutcome').textContent = pause ? 'Pausing…' : 'Resuming…';

  pauseInFlight.add(jobId);

  let result;
  try {
    const r = await fetch('/api/actions/pause-automation', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Origin': location.origin,
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify({ jobId, pause, idempotencyKey, clientStateVersion: stateVersion }),
    });
    result = await r.json();
    if (!r.ok && r.status === 409 && result.error === 'STALE_PAGE') {
      $('#pauseOutcome').className = 'outcome-warn';
      $('#pauseOutcome').textContent = '⚠ Page state stale. Refreshing…';
      setTimeout(() => { $('#pauseConfirmDialog').close(); load(); }, 1500);
      return;
    }
    if (!r.ok) {
      $('#pauseOutcome').className = 'outcome-error';
      $('#pauseOutcome').textContent = `✗ ${result.detail || result.error || 'Request failed'}`;
      $('#confirmPauseBtn').disabled = false;
      $('#confirmPauseBtn').textContent = pause ? '⏸ Retry' : '▶ Retry';
      pauseInFlight.delete(jobId);
      return;
    }
  } catch (err) {
    $('#pauseOutcome').className = 'outcome-error';
    $('#pauseOutcome').textContent = '✗ Network error — manual verification required.';
    $('#confirmPauseBtn').disabled = false;
    $('#confirmPauseBtn').textContent = pause ? '⏸ Retry' : '▶ Retry';
    pauseInFlight.delete(jobId);
    return;
  }

  // Apply 15s client-side cooldown (matches server PAUSE_COOLDOWN_JOB_MS)
  pauseCooldowns.set(jobId, Date.now() + 15_000);
  pauseInFlight.delete(jobId);

  // Optimistically update live enabled state map
  jobEnabledState.set(jobId, !pause);

  const outcome = result.outcome;
  const label = pause ? 'PAUSED' : 'RESUMED';
  if (outcome === 'PAUSED' || outcome === 'RESUMED') {
    $('#pauseOutcome').className = 'outcome-success';
    $('#pauseOutcome').textContent = `✓ ${label}`;
    setTimeout(() => { $('#pauseConfirmDialog').close(); load(); }, 2000);
  } else if (outcome === 'OUTCOME_UNKNOWN') {
    $('#pauseOutcome').className = 'outcome-warn';
    $('#pauseOutcome').textContent = `⚠ OUTCOME UNKNOWN — ${result.detail || 'Manual verification required.'}`;
    $('#confirmPauseBtn').textContent = 'Close';
    $('#confirmPauseBtn').disabled = false;
    $('#confirmPauseBtn').onclick = () => { $('#pauseConfirmDialog').close(); load(); };
  } else {
    $('#pauseOutcome').className = 'outcome-error';
    $('#pauseOutcome').textContent = `✗ FAILED — ${result.detail || 'Check timeline for details.'}`;
    $('#confirmPauseBtn').textContent = 'Close';
    $('#confirmPauseBtn').disabled = false;
    $('#confirmPauseBtn').onclick = () => { $('#pauseConfirmDialog').close(); load(); };
  }
}

// ─── RESTART GATEWAY ─────────────────────────────────────────────────────────

function restartCooldownRemaining() {
  return Math.max(0, restartCooldownExpiry - Date.now());
}

function renderRestartButton() {
  const container = $('#gatewayActions');
  if (!container) return;
  const isStale = stateVersion === null || stateVersion === '';
  const cdLeft = restartCooldownRemaining();
  const disabled = isStale || cdLeft > 0 || restartInFlight || gatewayReconnecting;
  let label, title;
  if (restartInFlight) { label = '\u23f3 Restarting\u2026'; title = 'Restart in progress'; }
  else if (gatewayReconnecting) { label = '\u21ba Reconnecting\u2026'; title = 'Waiting for Gateway to come back'; }
  else if (cdLeft > 0) { label = `\u21ba Restart (${Math.ceil(cdLeft/1000)}s)`; title = '5-minute cooldown active'; }
  else if (isStale) { label = '\u21ba Restart'; title = 'Page state stale \u2014 reload first'; }
  else { label = '\u21ba Restart Gateway'; title = 'Restart the OpenClaw Gateway service (drain first, then restart)'; }
  container.innerHTML = `<button class="restart-btn${disabled?' btn-disabled':''}" ${disabled?'disabled':''} title="${esc(title)}">${label}</button>`;
  if (!disabled) {
    container.querySelector('.restart-btn').onclick = () => confirmRestart();
  }
}

function confirmRestart() {
  // Read active runs count from current gateway metrics if available
  const activeEl = $('#strip .KNOWN, #work b');
  // Fetch live activeRuns from pre-fetched snapshot (stored in last render)
  const activeRunsText = (() => {
    const workEl = $('#work');
    if (!workEl) return '0';
    // Parse the 'Active' kv row value
    const kvs = workEl.querySelectorAll('.kv');
    for (const kv of kvs) {
      const label = kv.querySelector('.muted');
      if (label && label.textContent === 'Active') {
        const val = kv.querySelector('b');
        return val ? val.textContent : '0';
      }
    }
    return '0';
  })();
  const activeRuns = parseInt(activeRunsText, 10) || 0;
  const note = activeRuns > 0
    ? `${activeRuns} active run${activeRuns===1?'':'s'} will be drained before restart.`
    : 'No active runs.';
  $('#restartActiveRunsNote').textContent = note;
  $('#restartOutcome').hidden = true;
  $('#restartOutcome').className = '';
  $('#restartOutcome').textContent = '';
  $('#confirmRestartBtn').disabled = false;
  $('#confirmRestartBtn').textContent = '\u21ba Restart Gateway';
  $('#restartGatewayDialog').showModal();
}

async function executeRestart() {
  const idempotencyKey = uuidv4();
  $('#confirmRestartBtn').disabled = true;
  $('#confirmRestartBtn').textContent = '\u23f3 Restarting\u2026 draining active work';
  $('#restartOutcome').hidden = false;
  $('#restartOutcome').className = 'outcome-pending';
  $('#restartOutcome').textContent = 'Restarting\u2026 draining active work';
  $('#cancelRestartBtn').disabled = true;

  restartInFlight = true;
  renderRestartButton();

  const t0 = Date.now();
  let result;
  try {
    const r = await fetch('/api/actions/restart-gateway', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Origin': location.origin,
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify({ idempotencyKey, clientStateVersion: stateVersion }),
    });
    result = await r.json();
    if (!r.ok && r.status === 409 && result.error === 'STALE_PAGE') {
      $('#restartOutcome').className = 'outcome-warn';
      $('#restartOutcome').textContent = '\u26a0 Page state stale. Refreshing\u2026';
      restartInFlight = false;
      renderRestartButton();
      $('#cancelRestartBtn').disabled = false;
      setTimeout(() => { $('#restartGatewayDialog').close(); load(); }, 1500);
      return;
    }
    if (!r.ok) {
      const detail = result.detail || result.error || 'Request failed';
      $('#restartOutcome').className = 'outcome-error';
      $('#restartOutcome').textContent = `\u2717 ${detail}`;
      restartInFlight = false;
      renderRestartButton();
      $('#cancelRestartBtn').disabled = false;
      $('#confirmRestartBtn').disabled = false;
      $('#confirmRestartBtn').textContent = 'Close';
      $('#confirmRestartBtn').onclick = () => { $('#restartGatewayDialog').close(); load(); };
      return;
    }
  } catch (err) {
    $('#restartOutcome').className = 'outcome-error';
    $('#restartOutcome').textContent = '\u2717 Network error \u2014 manual verification required.';
    restartInFlight = false;
    renderRestartButton();
    $('#cancelRestartBtn').disabled = false;
    $('#confirmRestartBtn').disabled = false;
    $('#confirmRestartBtn').textContent = 'Close';
    $('#confirmRestartBtn').onclick = () => { $('#restartGatewayDialog').close(); load(); };
    return;
  }

  // Command sent. Apply client-side cooldown.
  restartCooldownExpiry = Date.now() + 300_000;
  restartInFlight = false;
  renderRestartButton();

  const outcome = result.outcome;

  if (outcome === 'RESTARTED') {
    // Gateway is restarting. Enter reconnect-wait mode.
    gatewayReconnecting = true;
    renderRestartButton();
    $('#restartOutcome').className = 'outcome-pending';
    $('#restartOutcome').textContent = 'Restarting\u2026 waiting for Gateway';
    // Wait for SSE to deliver a fresh snapshot (gateway back online)
    // The SSE stream stays alive; when acquirer reconnects, it pushes snapshot.
    // Poll our own /healthz to detect reconnect (cockpit is always up).
    let reconnected = false;
    const pollStart = Date.now();
    const poller = setInterval(async () => {
      try {
        const h = await fetch('/healthz').then(r => r.json());
        if (h.ok && !reconnected) {
          // cockpit is up; Gateway might still be restarting — SSE will confirm
          // once acquirer pushes a healthy snapshot, gatewayReconnecting clears in render()
        }
      } catch { /* cockpit is up, gateway may be mid-restart */ }
      if (!gatewayReconnecting || Date.now() - pollStart > 90_000) {
        clearInterval(poller);
        if (gatewayReconnecting) {
          // Timed out waiting for SSE reconnect
          gatewayReconnecting = false;
          renderRestartButton();
        }
      }
    }, 3_000);
    // Auto-close dialog after 3s, show in-tile status
    const reconnectedInMs = Date.now() - t0;
    setTimeout(() => {
      $('#restartOutcome').className = 'outcome-success';
      $('#restartOutcome').textContent = `\u2713 RESTARTED \u2014 reconnected in ${Math.round(reconnectedInMs/100)/10}s`;
      setTimeout(() => { $('#restartGatewayDialog').close(); load(); }, 3000);
    }, 500);
  } else if (outcome === 'OUTCOME_UNKNOWN') {
    gatewayReconnecting = false;
    $('#restartOutcome').className = 'outcome-warn';
    $('#restartOutcome').textContent = `\u26a0 OUTCOME UNKNOWN \u2014 ${result.detail || 'Check Gateway manually.'}` ;
    $('#cancelRestartBtn').disabled = false;
    $('#confirmRestartBtn').textContent = 'Close';
    $('#confirmRestartBtn').disabled = false;
    $('#confirmRestartBtn').onclick = () => { $('#restartGatewayDialog').close(); load(); };
  } else {
    gatewayReconnecting = false;
    $('#restartOutcome').className = 'outcome-error';
    $('#restartOutcome').textContent = `\u2717 RESTART_FAILED \u2014 ${result.detail || 'Manual intervention required.'}` ;
    $('#cancelRestartBtn').disabled = false;
    $('#confirmRestartBtn').textContent = 'Close';
    $('#confirmRestartBtn').disabled = false;
    $('#confirmRestartBtn').onclick = () => { $('#restartGatewayDialog').close(); load(); };
  }
}

// ─────────────────────────────────────────────────────────────────────────────

function confirmRun(jobId, jobName) {
  $('#confirmJobName').textContent = jobName;
  $('#confirmJobId').textContent = jobId;
  $('#runConfirmDialog').dataset.jobid = jobId;
  $('#runConfirmDialog').dataset.jobname = jobName;
  $('#runOutcome').hidden = true;
  $('#runOutcome').className = '';
  $('#runOutcome').textContent = '';
  $('#confirmRunBtn').disabled = false;
  $('#confirmRunBtn').textContent = '▶ Run now';
  $('#runConfirmDialog').showModal();
}

async function executeRun(jobId, jobName) {
  const idempotencyKey = uuidv4();
  $('#confirmRunBtn').disabled = true;
  $('#confirmRunBtn').textContent = '⏳ Triggering…';
  $('#runOutcome').hidden = false;
  $('#runOutcome').className = 'outcome-pending';
  $('#runOutcome').textContent = 'Sending trigger…';

  jobInFlight.add(jobId);

  let result;
  try {
    const r = await fetch('/api/actions/run-automation', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Origin': location.origin,
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify({ jobId, idempotencyKey, clientStateVersion: stateVersion }),
    });
    result = await r.json();
    if (!r.ok && r.status === 409 && result.error === 'STALE_PAGE') {
      // Stale page — refresh state and abort
      $('#runOutcome').className = 'outcome-warn';
      $('#runOutcome').textContent = '⚠ Page state stale. Refreshing…';
      setTimeout(() => { $('#runConfirmDialog').close(); load(); }, 1500);
      return;
    }
    if (!r.ok) {
      $('#runOutcome').className = 'outcome-error';
      $('#runOutcome').textContent = `✗ ${result.detail || result.error || 'Request failed'}`;
      $('#confirmRunBtn').disabled = false;
      $('#confirmRunBtn').textContent = '▶ Retry';
      return;
    }
  } catch (err) {
    $('#runOutcome').className = 'outcome-error';
    $('#runOutcome').textContent = '✗ Network error — manual verification required.';
    $('#confirmRunBtn').disabled = false;
    $('#confirmRunBtn').textContent = '▶ Retry';
    jobInFlight.delete(jobId);
    return;
  }

  // Apply 30s client-side cooldown
  jobCooldowns.set(jobId, Date.now() + 30_000);
  jobInFlight.delete(jobId);

  const outcome = result.outcome;
  if (outcome === 'STARTED') {
    $('#runOutcome').className = 'outcome-success';
    $('#runOutcome').textContent = '✓ Run triggered — verifying…';
    // Auto-close after 2s, reload to show timeline entry
    setTimeout(() => { $('#runConfirmDialog').close(); load(); }, 2000);
  } else if (outcome === 'OUTCOME_UNKNOWN') {
    $('#runOutcome').className = 'outcome-warn';
    $('#runOutcome').textContent = `⚠ OUTCOME UNKNOWN — ${result.detail || 'Manual verification required.'}`;
    $('#confirmRunBtn').textContent = 'Close';
    $('#confirmRunBtn').disabled = false;
    $('#confirmRunBtn').onclick = () => { $('#runConfirmDialog').close(); load(); };
  } else {
    $('#runOutcome').className = 'outcome-error';
    $('#runOutcome').textContent = `✗ FAILED — ${result.detail || 'Check timeline for details.'}`;
    $('#confirmRunBtn').textContent = 'Close';
    $('#confirmRunBtn').disabled = false;
    $('#confirmRunBtn').onclick = () => { $('#runConfirmDialog').close(); load(); };
  }
}

// Auth form
$('#authForm').onsubmit = async e => {
  e.preventDefault();
  const payload = mode === 'enroll'
    ? { token: $('#token').value, password: $('#password').value }
    : { password: $('#password').value };
  const r = await fetch(`/api/${mode}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Origin': location.origin },
    body: JSON.stringify(payload),
  });
  const x = await r.json();
  if (!r.ok) { $('#authError').textContent = x.error; return; }
  csrf = x.csrf || csrf;
  if (x.recoveryCodes) { $('#codes').textContent = x.recoveryCodes.join('\n'); $('#recovery').showModal(); }
  else load();
};

$('#saved').onclick = () => { $('#recovery').close(); load(); };

$('#logout').onclick = async () => {
  await fetch('/api/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Origin': location.origin, 'X-CSRF-Token': csrf },
    body: '{}',
  });
  location.reload();
};

// Restart Gateway dialog buttons
$('#cancelRestartBtn').onclick = () => { $('#restartGatewayDialog').close(); load(); };
$('#confirmRestartBtn').onclick = () => executeRestart();

// Run confirm dialog buttons
$('#cancelRunBtn').onclick = () => $('#runConfirmDialog').close();
$('#confirmRunBtn').onclick = () => {
  const d = $('#runConfirmDialog');
  executeRun(d.dataset.jobid, d.dataset.jobname);
};

// Pause confirm dialog buttons
$('#cancelPauseBtn').onclick = () => $('#pauseConfirmDialog').close();
$('#confirmPauseBtn').onclick = () => {
  const d = $('#pauseConfirmDialog');
  executePause(d.dataset.jobid, d.dataset.jobname, d.dataset.pause === 'true');
};

bootstrap().then(() => {
  const es = new EventSource('/api/stream');
  es.addEventListener('snapshot', load);
});
