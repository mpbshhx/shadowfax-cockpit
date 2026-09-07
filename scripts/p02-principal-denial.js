/**
 * GAP 3 — P02 separate-principal denial verification.
 *
 * P02 frozen criterion: A separate unprivileged principal must be denied
 * read/list/write on the protected data directory.
 *
 * Constraint: This harness cannot create a system user (requires admin rights).
 * It therefore performs the strongest available proof without a separate
 * principal: verify that the protected DACL on the data directory grants access
 * ONLY to the allowed SIDs (service SID, SYSTEM, Administrators), and prove
 * that no other SID appears in the effective access grant.
 *
 * Evidence class: PARTIALLY VERIFIED.
 * Reason: A real runtime denial test would require a separately provisioned
 * unprivileged principal (e.g., a low-privilege Windows user account).
 * This harness confirms the DACL is correct and inheritance is blocked, which
 * is a necessary but not sufficient proof of actual runtime denial.
 *
 * Read-only; no mutations to OpenClaw state or production data.
 * Node built-ins only; no external package installs.
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const outputPath = process.argv[2] ? path.resolve(process.argv[2]) : null;

// ── Step 1: Create an isolated test directory with the protected DACL ────────
// We apply the cockpit's own protection script to an isolated temp dir,
// then verify the resulting DACL with Get-Acl.

const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cockpit-p02-'));
const scriptPath = path.resolve(import.meta.dirname, '..', 'scripts', 'windows-protect-data.ps1');

let applyResult = null;
let verifyResult = null;
let daclAnalysis = null;
let cleanupOk = false;

try {
  // Apply the protection
  const apply = spawnSync('powershell', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', scriptPath, '-Path', testDir,
  ], { encoding: 'utf8', windowsHide: true, timeout: 15000 });

  applyResult = {
    exitCode: apply.status,
    stdout: apply.stdout?.trim() || null,
    stderr: apply.stderr?.trim() || null,
    error: apply.error?.message || null,
  };

  if (apply.status === 0) {
    let appliedDacl = null;
    try { appliedDacl = JSON.parse(apply.stdout?.trim() || 'null'); } catch { /* ignore */ }

    // ── Step 2: Verify with Get-Acl — enumerate all ACEs and check no unexpected SIDs ──
    const verifyPs = `
$ErrorActionPreference = 'Stop'
$dir = '${testDir.replace(/'/g, "''")}'
$acl = Get-Acl -LiteralPath $dir
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$systemSid = 'S-1-5-18'
$adminsSid = 'S-1-5-32-544'
$allowedSids = @($currentSid, $systemSid, $adminsSid) | Sort-Object -Unique

$aces = @($acl.Access | ForEach-Object {
  $sid = $null
  try { $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
  [pscustomobject]@{
    principal = $_.IdentityReference.Value
    sid = $sid
    accessType = $_.AccessControlType.ToString()
    rights = $_.FileSystemRights.ToString()
    inherited = $_.IsInherited
    inheritanceFlags = $_.InheritanceFlags.ToString()
    propagationFlags = $_.PropagationFlags.ToString()
  }
})

$unexpectedSids = @($aces | Where-Object { $_.sid -and $_.sid -notin $allowedSids } | Select-Object -ExpandProperty sid | Sort-Object -Unique)
$allAllowed = @($aces | Where-Object { $_.sid -and $_.sid -in $allowedSids })
$isProtected = $acl.AreAccessRulesProtected
$hasInherited = @($aces | Where-Object { $_.inherited }).Count -gt 0

[pscustomobject]@{
  path = $dir
  currentSid = $currentSid
  allowedSids = @($allowedSids)
  totalAces = $aces.Count
  isProtected = $isProtected
  hasInheritedAces = $hasInherited
  unexpectedSids = @($unexpectedSids)
  unexpectedCount = $unexpectedSids.Count
  allAces = @($aces)
  denyAnyPrincipal = @($aces | Where-Object { $_.accessType -eq 'Deny' }).Count -gt 0
} | ConvertTo-Json -Depth 6 -Compress
`;

    const verify = spawnSync('powershell', [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', verifyPs,
    ], { encoding: 'utf8', windowsHide: true, timeout: 15000 });

    verifyResult = {
      exitCode: verify.status,
      stderr: verify.stderr?.trim() || null,
      error: verify.error?.message || null,
    };

    if (verify.status === 0) {
      try {
        daclAnalysis = JSON.parse(verify.stdout?.trim() || 'null');
      } catch (parseErr) {
        verifyResult.parseError = parseErr.message;
        verifyResult.rawOutput = verify.stdout?.trim().slice(0, 512);
      }
    }
  }

  // ── Step 3: Also verify Get-ChildItem shows no access for Everyone / Users ──
  // Attempt to test effective access using accesschk if available, otherwise
  // document the limitation.
  const accesschkCheck = spawnSync('where', ['accesschk'], { encoding: 'utf8', windowsHide: true, timeout: 3000 });
  const accesschkAvailable = accesschkCheck.status === 0;

  let effectiveAccessCheck = null;
  if (accesschkAvailable) {
    const ac = spawnSync('accesschk', ['-d', '-nobanner', testDir], {
      encoding: 'utf8', windowsHide: true, timeout: 10000,
    });
    effectiveAccessCheck = {
      tool: 'accesschk',
      exitCode: ac.status,
      output: ac.stdout?.trim().slice(0, 1024) || null,
      stderr: ac.stderr?.trim().slice(0, 256) || null,
    };
  } else {
    effectiveAccessCheck = {
      tool: 'accesschk',
      available: false,
      note: 'accesschk not found in PATH. Effective-access verification limited to DACL inspection.',
    };
  }

  // ── Step 4: Verify Users group (S-1-5-32-545) is not in DACL ──────────────
  // The Users group SID is S-1-5-32-545. If it appears in the ACL with any
  // Allow entry, the protection is incomplete.
  const usersSid = 'S-1-5-32-545';
  const everyoneSid = 'S-1-1-0';
  const authenticatedUsersSid = 'S-1-5-11';

  let privilegedSidsAbsent = null;
  if (daclAnalysis && Array.isArray(daclAnalysis.allAces)) {
    const allSids = daclAnalysis.allAces.map(a => a.sid).filter(Boolean);
    privilegedSidsAbsent = {
      usersSid,
      usersAbsent: !allSids.includes(usersSid),
      everyoneSid,
      everyoneAbsent: !allSids.includes(everyoneSid),
      authenticatedUsersSid,
      authenticatedUsersAbsent: !allSids.includes(authenticatedUsersSid),
      note: 'Absence of these SIDs from the DACL means no unprivileged user has a grant via these groups.',
    };
  }

  // ── Determine P02 evidence class ──────────────────────────────────────────
  const daclCorrect = daclAnalysis &&
    daclAnalysis.isProtected === true &&
    daclAnalysis.hasInheritedAces === false &&
    daclAnalysis.unexpectedCount === 0;

  const privilegedGroupsAbsent = privilegedSidsAbsent &&
    privilegedSidsAbsent.usersAbsent &&
    privilegedSidsAbsent.everyoneAbsent &&
    privilegedSidsAbsent.authenticatedUsersAbsent;

  const evidenceClass = daclCorrect && privilegedGroupsAbsent
    ? 'PARTIALLY_VERIFIED'
    : 'FAILED';

  const result = {
    observedAt: new Date().toISOString(),
    evidenceClass,
    reason: evidenceClass === 'PARTIALLY_VERIFIED'
      ? 'DACL inspection confirms no unprivileged principal SID has any grant entry. ' +
        'Users (S-1-5-32-545), Everyone (S-1-1-0), and Authenticated Users (S-1-5-11) ' +
        'are absent from the ACL. Inheritance is blocked. No separate runtime denial ' +
        'test was performed because creating a test user account requires admin rights ' +
        'not available in this harness scope.'
      : 'DACL inspection failed or found unexpected SIDs. See daclAnalysis.',
    frozenCriterion: 'P02: Separate unprivileged principal read/list/write must be denied.',
    limitation: 'A complete P02 proof requires a separate unprivileged Windows user account ' +
      'to attempt filesystem access. That account was not created because doing so ' +
      'requires elevated (admin) privileges not granted in this harness. ' +
      'The strongest available evidence is DACL structure verification showing ' +
      'no grant for unprivileged SIDs.',
    applyResult,
    verifyResult,
    daclAnalysis,
    privilegedSidsAbsent,
    effectiveAccessCheck,
  };

  if (outputPath) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    const json = `${JSON.stringify(result, null, 2)}\n`;
    fs.writeFileSync(outputPath, json);
    const hash = crypto.createHash('sha256').update(json).digest('hex').toUpperCase();
    console.error(`[p02-principal-denial] Written: ${outputPath}`);
    console.error(`[p02-principal-denial] Evidence class: ${evidenceClass}`);
    console.error(`[p02-principal-denial] SHA-256: ${hash}`);
  } else {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  }
} finally {
  try {
    fs.rmSync(testDir, { recursive: true, force: true });
    cleanupOk = true;
  } catch (e) {
    console.error(`[p02-principal-denial] Cleanup failed: ${e.message}`);
  }
}
