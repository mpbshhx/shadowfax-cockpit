import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const ACL_SCRIPT = path.resolve(import.meta.dirname, '..', 'scripts', 'windows-protect-data.ps1');

function runWindowsAcl(target, verifyOnly = false) {
  const args = ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ACL_SCRIPT, '-Path', target];
  if (verifyOnly) args.push('-VerifyOnly');
  const result = spawnSync('powershell', args, { encoding: 'utf8', windowsHide: true, timeout: 15000 });
  if (result.error) throw Object.assign(new Error(`DATA_DACL_${verifyOnly ? 'VERIFY' : 'APPLY'}_FAILED`), { cause: result.error });
  if (result.status !== 0) throw Object.assign(new Error(`DATA_DACL_${verifyOnly ? 'VERIFY' : 'APPLY'}_FAILED`), { code: 'DATA_DACL_FAILED', detail: String(result.stderr || result.stdout).trim() });
  let parsed;
  try { parsed = JSON.parse(String(result.stdout).trim()); } catch { throw Object.assign(new Error('DATA_DACL_VERIFY_INVALID'), { code: 'DATA_DACL_FAILED' }); }
  if (!parsed.protected) throw Object.assign(new Error('DATA_DACL_VERIFY_FAILED'), { code: 'DATA_DACL_FAILED' });
  return parsed;
}

export function protectDataDirectory(dir, { platform = process.platform, windowsAcl = runWindowsAcl } = {}) {
  const resolved = path.resolve(dir);
  fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(resolved);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('unsafe data path');
  if (platform === 'win32') return windowsAcl(resolved, false);
  fs.chmodSync(resolved, 0o700);
  return { path: resolved, protected: true, mechanism: 'mode-0700' };
}

export function verifyDataDirectoryProtection(dir, { platform = process.platform, windowsAcl = runWindowsAcl } = {}) {
  const resolved = path.resolve(dir);
  if (platform === 'win32') return windowsAcl(resolved, true);
  const mode = fs.statSync(resolved).mode & 0o777;
  if (mode !== 0o700) throw Object.assign(new Error('DATA_MODE_VERIFY_FAILED'), { code: 'DATA_DACL_FAILED' });
  return { path: resolved, protected: true, mechanism: 'mode-0700' };
}
