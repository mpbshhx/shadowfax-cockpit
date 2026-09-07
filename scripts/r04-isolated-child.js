import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const output = path.resolve(process.argv[2] || '../evidence/phase1a-r04-isolated-child.json');
const port = 38350 + Math.floor(Math.random() * 100);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cockpit-r04-'));
const preload = path.join(dir, 'rss-preload.cjs');
fs.writeFileSync(preload, "const real=process.memoryUsage;process.memoryUsage=function(){return {...real(),rss:256*1024*1024+1}};\n");
const startedAt = Date.now();
const child = spawn(process.execPath, ['--require', preload, 'server.js'], { cwd: path.resolve(import.meta.dirname, '..'), env: { ...process.env, HOST: '127.0.0.1', PORT: String(port), COCKPIT_DATA_DIR: path.join(dir, 'data'), COCKPIT_DISABLE_ACQUISITION: '1' }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
let stdout = '', stderr = ''; child.stdout.on('data', d => stdout += d); child.stderr.on('data', d => stderr += d);
const result = await Promise.race([
  new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal, elapsedMs: Date.now() - startedAt }))),
  new Promise(resolve => setTimeout(() => resolve({ timeout: true, elapsedMs: Date.now() - startedAt }), 70000)),
]);
if (result.timeout) child.kill('SIGTERM');
await new Promise(resolve => child.exitCode === null ? child.once('exit', resolve) : resolve());
fs.rmSync(dir, { recursive: true, force: true });
const pass = !result.timeout && result.code === 75 && result.elapsedMs >= 60000 && result.elapsedMs < 66000;
const report = { status: pass ? 'PASS' : 'FAIL', isolatedChild: true, allocatedHostMemory: false, syntheticRssBytes: 256 * 1024 ** 2 + 1, expected: 'exit code 75 after 60 seconds of sustained over-limit RSS', observed: result, stdoutHash: process.getBuiltinModule('node:crypto').createHash('sha256').update(stdout).digest('hex'), stderrHash: process.getBuiltinModule('node:crypto').createHash('sha256').update(stderr).digest('hex') };
fs.mkdirSync(path.dirname(output), { recursive: true }); fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify(report)); process.exitCode = pass ? 0 : 1;
