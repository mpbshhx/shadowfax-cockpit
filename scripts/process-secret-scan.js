import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';

const output = path.resolve(process.argv[2] || '../evidence/phase1a-process-secret-scan.json');
const suspiciousName = /(?:password|passwd|secret|token|cookie|session|authorization|recovery|bootstrap)/i;
const safeEnvNames = new Set(['COCKPIT_DATA_DIR', 'COCKPIT_DISABLE_ACQUISITION']);
const findings = [];

function classify(source, name, value) {
  if (suspiciousName.test(name) && !safeEnvNames.has(name)) findings.push({ source, field: 'name', nameHash: hash(name) });
  if (/(?:sk-[\w-]{8,}|Bearer\s+\S+|__Host-cockpit=|(?:password|token|cookie|session|authorization|recovery)\s*[=:]\s*\S+)/i.test(String(value))) findings.push({ source, field: 'value', nameHash: hash(name) });
}
function hash(value) { return process.getBuiltinModule('node:crypto').createHash('sha256').update(String(value)).digest('hex'); }

const appDir = path.resolve(import.meta.dirname, '..');
const childArgs = ['server.js'];
const childEnv = { PATH: process.env.PATH || '', SYSTEMROOT: process.env.SYSTEMROOT || '', TEMP: process.env.TEMP || '', TMP: process.env.TMP || '', USERPROFILE: process.env.USERPROFILE || '', HOST: '127.0.0.1', PORT: '37991', COCKPIT_DATA_DIR: path.join(process.env.TEMP || '.', `cockpit-s04-${process.pid}`), COCKPIT_DISABLE_ACQUISITION: '1' };
for (const [name, value] of Object.entries(childEnv)) classify('cockpit-child-environment', name, value);
for (const [index, value] of childArgs.entries()) classify('cockpit-child-argument', `argv-${index}`, value);
const child = spawn(process.execPath, childArgs, { cwd: appDir, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
let stdout = '', stderr = '';
child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(Error('startup timeout')), 5000); child.stdout.on('data', () => { if (stdout.includes('listening')) { clearTimeout(timer); resolve(); } }); child.once('error', reject); child.once('exit', code => reject(Error(`early exit ${code}`))); });
const ps = spawn('powershell', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', `$p=Get-CimInstance Win32_Process -Filter "ProcessId=${child.pid}"; [pscustomobject]@{CommandLine=$p.CommandLine}|ConvertTo-Json -Compress`], { windowsHide: true });
let processJson = ''; ps.stdout.on('data', d => { processJson += d; });
await new Promise(resolve => ps.once('exit', resolve));
const commandLine = JSON.parse(processJson).CommandLine || '';
classify('child-command-line', 'commandLine', commandLine);
child.kill('SIGTERM'); await new Promise(resolve => child.once('exit', resolve));
fs.rmSync(path.join(process.env.TEMP || '.', `cockpit-s04-${process.pid}`), { recursive: true, force: true });
const report = { status: findings.length ? 'FAIL' : 'PASS', checked: ['cockpit generated child argument names and values', 'cockpit generated child environment names and values', 'observed cockpit child command line'], retainedValues: false, findingCount: findings.length, findings, childStdoutHash: hash(stdout), childStderrHash: hash(stderr) };
fs.mkdirSync(path.dirname(output), { recursive: true }); fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify(report));
process.exitCode = findings.length ? 1 : 0;
