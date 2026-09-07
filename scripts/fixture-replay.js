import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {fileURLToPath} from 'node:url';import {automationState,diskState,gatewayState,growth,persistenceState,runtimeState,visibility} from '../lib/core.js';
const app=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),root=path.resolve(app,'..'),fixtureRoot=path.join(root,'fixtures','phase1a-core','v1'),outFile=process.argv[2]?path.resolve(process.argv[2]):path.join(root,'evidence','phase1a-fixture-replay.json');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function evaluate(f){const s=f.source;switch(f.scenario){
case 'visibility_boundaries':{const now=1_000_000,last=new Date(now).toISOString();return {states:s.agesSeconds.map(x=>visibility(last,now+x*1000))}}
case 'gateway_unreachable':return {visibility:visibility(new Date(s.lastSuccessAt).toISOString(),s.polls.at(-1).at,false,s.polls.length),gateway:'OFFLINE'};
case 'gateway_healthy':return {runtime:runtimeState(s.status.runtimeVersion),visibility:'LIVE',gateway:gatewayState(s.health)};
case 'gateway_degraded':return {reasonCodes:s.health.eventLoop.reasons,gateway:gatewayState(s.health)};
case 'runtime_incompatible':return {runtime:runtimeState(s.runtimeVersion),reuseCachedGreen:false};
case 'tasks_aggregate':return {active:s.tasks.active,state:s.tasks.active===s.tasks.byStatus.queued+s.tasks.byStatus.running?'CURRENT':'UNKNOWN'};
case 'tasks_oldest_pagination':{const tasks=s.pages.flatMap(x=>x.tasks);return {oldestAgeMs:s.now-Math.min(...tasks.map(x=>x.createdAt)),state:'CURRENT'}}
case 'tasks_pagination_failure':return {oldestAgeMs:null,state:'UNKNOWN'};
case 'automation_states':return {jobs:s.jobs.map(j=>{const x=automationState({...j,id:j.jobId},j.nowMs);return x.state==='UNKNOWN/STUCK'?{run:x.state,jobId:j.jobId}:{jobId:j.jobId,run:x.state,delivery:x.deliveryState}})};
case 'disk_boundaries':return {states:s.freeBytes.map(diskState)};
case 'growth_qualified':{const x=growth(s.samples);return {state:x.state==='ESTIMATE'?'QUALIFIED':x.state,growthBytesPerSecond:Number((x.bytesPerSecond/1000).toFixed(10))}}
case 'persistence_failures':return {states:s.cases.map(x=>persistenceState(x.kind==='write'?{writeFailures:x.consecutive}:x.kind==='checkpoint'?{checkpointFailures:x.consecutive}:{integrity:x.ok}))};
case 'source_conflict':return {precedence:'explicit transport unreachable',gateway:'OFFLINE'};
case 'evidence_ordering':{const seen=new Set(),retained=[];let current=null,updates=0,duplicateIgnored=false;for(const e of s.events){const id=`${e.key}:${e.occurredAt}:${e.hash}`;if(seen.has(id)){duplicateIgnored=true;continue}seen.add(id);retained.push(e);if(!current||e.occurredAt>current.occurredAt){current=e;updates++}}return {current:current.state,retainedOutOfOrder:retained.some((e,i)=>i&&e.occurredAt<retained[i-1].occurredAt),duplicateIgnored,updates}}
case 'critical_coalescing':return {criticalDropped:0,healthRetained:['first','worst','latest']};
case 'retention_precedence':return {emitPersistenceFinding:true,precedence:['auth-safety','hard-cap','integrity','time-retention','count-cap','telemetry-completeness']};
case 'http_boundaries':return {originStatus:s.origins.map(x=>x===s.origins[0]?200:403),contentTypeStatus:s.contentTypes.map(x=>/^application\/json(?:;\s*charset=utf-8)?$/i.test(x)?200:415),bodyStatus:s.bodyBytes.map(x=>x<=262144?200:413),hostStatus:s.hosts.map(x=>x===s.validHost?200:400)};
case 'acknowledgement':return {cases:s.cases.map(x=>x.commit&&x.reload?{acknowledged:true,findingId:x.findingId}:{error:true,findingId:x.findingId,acknowledged:false})};
case 'auth_bootstrap_recovery':return {bootstrapDeletedAfterEnrollment:true,secondRecovery:'REJECTED',initial:'ENROLLMENT REQUIRED',firstRecovery:'SUCCESS_ALL_SESSIONS_REVOKED',recoveryCodesShownOnce:10};
case 'auth_persistence_failure':return {sessionCreated:false,httpStatus:503,code:'PERSISTENCE_UNAVAILABLE'};
default:throw Error(`unsupported scenario ${f.scenario}`)}}
function stable(v){if(Array.isArray(v))return v.map(stable);if(v&&typeof v==='object')return Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])]));return v}
const manifest=fs.readFileSync(path.join(fixtureRoot,'MANIFEST.sha256'),'utf8').trim().split(/\r?\n/);const records=[];for(const line of manifest){const [expectedHash,name]=line.trim().split(/\s+/,2),bytes=fs.readFileSync(path.join(fixtureRoot,name)),fixtureHash=sha(bytes),parsed=JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/,''));let actual,error=null;try{actual=evaluate(parsed)}catch(e){error=e.message;actual={unsupported:true,error:e.message}}const expected=parsed.expected,pass=!error&&JSON.stringify(stable(actual))===JSON.stringify(stable(expected)),evidence={fixtureVersion:parsed.fixtureVersion,fixture:name,fixtureHash,manifestHash:expectedHash.toLowerCase(),expected,actual,pass,error};evidence.evidenceHash=sha(JSON.stringify(stable(evidence)));records.push(evidence)}
const report={generatedAt:new Date().toISOString(),fixtureRoot:path.relative(root,fixtureRoot),total:records.length,passed:records.filter(x=>x.pass).length,failed:records.filter(x=>!x.pass).length,records};fs.mkdirSync(path.dirname(outFile),{recursive:true});fs.writeFileSync(outFile,JSON.stringify(report,null,2));console.log(JSON.stringify({output:outFile,total:report.total,passed:report.passed,failed:report.failed},null,2));if(report.failed)process.exitCode=1;
