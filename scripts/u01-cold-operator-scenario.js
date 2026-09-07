import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const output = path.resolve(process.argv[2] || '../evidence/u01-cold-operator-scenario.json');
const scenarios = [
  { id: 'gateway-offline', primaryFault: 'Gateway offline', gateway: 'OFFLINE', visibility: 'OFFLINE', evidence: 'Three consecutive health failures; last complete reconciliation 96 seconds ago', distinction: 'Gateway failure' },
  { id: 'visibility-stale', primaryFault: 'Visibility stale', gateway: 'UNKNOWN', visibility: 'STALE', evidence: 'Status source timed out; health succeeded; last complete reconciliation 44 seconds ago', distinction: 'Cockpit blindness' },
  { id: 'low-disk', primaryFault: 'Low disk', gateway: 'HEALTHY', visibility: 'LIVE', evidence: 'Free bytes 2,684,354,559; storage state READ-ONLY RECOVERY', distinction: 'Cockpit persistence risk' },
  { id: 'persistence-failure', primaryFault: 'Persistence failure', gateway: 'HEALTHY', visibility: 'LIVE', evidence: 'Two consecutive checkpoint failures; persistence PERSISTENCE DEGRADED', distinction: 'Cockpit persistence failure' },
  { id: 'runtime-incompatible', primaryFault: 'Runtime incompatible', gateway: 'HEALTHY', visibility: 'LIVE', evidence: 'Observed runtime 2026.9.2; supported runtime 2026.9.1', distinction: 'Source incompatibility' },
  { id: 'automation-terminal', primaryFault: 'Automation terminal failure', gateway: 'HEALTHY', visibility: 'LIVE', evidence: 'Job daily-report run failed; delivery succeeded', distinction: 'Automation failure' },
];
const seed = process.argv[3] || 'phase1a-u01-v1';
const index = crypto.createHash('sha256').update(seed).digest().readUInt32BE(0) % scenarios.length;
const scenario = scenarios[index];
const report = {
  status: 'READY_NOT_EXECUTED',
  frozenLimitSeconds: 300,
  terminalUseAllowed: false,
  seedHash: crypto.createHash('sha256').update(seed).digest('hex'),
  scenario: { id: scenario.id, displayedCockpit: { gateway: scenario.gateway, visibility: scenario.visibility, primaryEvidence: scenario.evidence } },
  operatorInstructions: 'Give this artifact and a rendered cockpit showing displayedCockpit to a person who has not worked on the build. Start a monotonic timer. Ask for the primary fault, whether it is Gateway failure or cockpit blindness, and the exact displayed evidence. Stop at 300 seconds.',
  evaluator: { passOnlyIf: ['answer primaryFault exactly', 'answer distinction exactly', 'cite primaryEvidence materially', 'elapsedSeconds <= 300', 'usedTerminal is false'], expectedAnswerCommitment: crypto.createHash('sha256').update(JSON.stringify({ primaryFault: scenario.primaryFault, distinction: scenario.distinction, evidence: scenario.evidence })).digest('hex') },
  result: null,
  limitation: 'No cold human execution is claimed. An independent operator must execute and record the result.'
};
fs.mkdirSync(path.dirname(output), { recursive: true }); fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify({ status: report.status, scenario: scenario.id, output }));
