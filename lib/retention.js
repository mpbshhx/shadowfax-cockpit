import fs from 'node:fs';
import path from 'node:path';

export const RETENTION = Object.freeze({
  samples: { maxAgeMs: 14 * 864e5, maxCount: 50000 },
  aggregates: { maxAgeMs: 90 * 864e5, maxCount: 5000 },
  findings: { maxAgeMs: 90 * 864e5, maxCount: 100000 },
  automations: { maxAgeMs: 30 * 864e5, maxCount: 50000 },
  authFailures: { maxAgeMs: 30 * 864e5, maxCount: 10000 },
  sessions: { expiryGraceMs: 864e5, maxCount: 10000 },
  artifacts: { cleanMaxAgeMs: 14 * 864e5, failedMetadataMaxAgeMs: 30 * 864e5 },
  logs: { maxFiles: 8, maxFileBytes: 8 * 1024 ** 2, maxTotalBytes: 64 * 1024 ** 2 },
});

export function pruneTimed(items, { now, maxAgeMs, maxCount, time = x => Date.parse(x.observedAt ?? x.occurredAt ?? x.at) }) {
  return items.filter(item => Number.isFinite(time(item)) && now - time(item) <= maxAgeMs).slice(-maxCount);
}

export function retentionPrecedence({ authSafety = false, hardCap = false, integrity = false, timeExpired = false, countExceeded = false } = {}) {
  if (authSafety) return 'AUTHENTICATION_SAFETY';
  if (hardCap) return 'HARD_CAP_OR_FREE_SPACE';
  if (integrity) return 'INTEGRITY';
  if (timeExpired) return 'TIME';
  if (countExceeded) return 'COUNT';
  return 'COMPLETENESS';
}

export function artifactExpired({ kind, createdAtMs }, now) {
  const age = now - createdAtMs;
  return kind === 'failed-metadata' ? age > RETENTION.artifacts.failedMetadataMaxAgeMs : age > RETENTION.artifacts.cleanMaxAgeMs;
}

export function ageArtifacts(root, now = Date.now()) {
  const removed = [];
  if (!fs.existsSync(root)) return removed;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const file = path.join(root, entry.name);
    const stat = fs.statSync(file);
    const kind = entry.name.endsWith('.failed.json') ? 'failed-metadata' : 'clean';
    if (artifactExpired({ kind, createdAtMs: stat.mtimeMs }, now)) {
      fs.unlinkSync(file);
      removed.push({ class: kind, nameHashInput: entry.name });
    }
  }
  return removed;
}

export function logAdmission(files, incomingBytes = 0) {
  const sizes = files.map(Number);
  const total = sizes.reduce((a, b) => a + b, 0);
  return {
    rotate: sizes.length >= RETENTION.logs.maxFiles || (sizes.at(-1) || 0) + incomingBytes > RETENTION.logs.maxFileBytes,
    admitted: sizes.length <= RETENTION.logs.maxFiles && total + incomingBytes <= RETENTION.logs.maxTotalBytes,
    files: sizes.length,
    totalBytes: total,
  };
}

export function backupLike(name) {
  return /(?:\.bak(?:\.|$)|\.backup(?:\.|$)|\.sqlite(?:[-._])?(?:copy|backup)|(?:^|[-_.])export(?:[-_.]|$))/i.test(name);
}
