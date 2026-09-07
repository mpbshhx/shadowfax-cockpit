export const RETRY_DELAYS_MS=Object.freeze([1000,2000,4000,8000,15000]);

export function retryable(error){
  const status=Number(error?.status??error?.statusCode);
  if(Number.isFinite(status)) return status>=500&&status<=599;
  if(error?.kind==='timeout'||error?.kind==='transport') return true;
  return ['ETIMEDOUT','ECONNRESET','ECONNREFUSED','EPIPE','ENETUNREACH','EHOSTUNREACH'].includes(error?.code);
}

export class OutboundBudget {
  constructor({rate=8,capacity=16,maxQueue=32,clock=()=>Date.now(),setTimer=setTimeout,clearTimer=clearTimeout,random=Math.random}={}){
    this.rate=rate;this.capacity=capacity;this.maxQueue=maxQueue;this.clock=clock;this.setTimer=setTimer;this.clearTimer=clearTimer;this.random=random;
    this.tokens=capacity;this.last=clock();this.queue=[];this.coalesced=new Map();this.timer=null;
  }
  refill(){const now=this.clock(),elapsed=Math.max(0,now-this.last);this.tokens=Math.min(this.capacity,this.tokens+elapsed*this.rate/1000);this.last=now}
  schedule(run,{critical=false,key=null}={}){
    return new Promise((resolve,reject)=>{
      this.refill();
      if(this.tokens>=1&&this.queue.length===0){this.tokens-=1;Promise.resolve().then(run).then(resolve,reject);return}
      if(!critical&&key&&this.coalesced.has(key)){
        const item=this.coalesced.get(key);item.run=run;item.waiters.push({resolve,reject});return
      }
      if(this.queue.length>=this.maxQueue){reject(Object.assign(Error('OUTBOUND_QUEUE_FULL'),{code:'OUTBOUND_QUEUE_FULL'}));return}
      const item={run,critical,key,waiters:[{resolve,reject}]};this.queue.push(item);if(!critical&&key)this.coalesced.set(key,item);this.arm();
    })
  }
  arm(){if(this.timer||!this.queue.length)return;this.refill();const wait=Math.max(1,Math.ceil((1-this.tokens)*1000/this.rate));this.timer=this.setTimer(()=>{this.timer=null;this.drain()},wait)}
  drain(){this.refill();while(this.tokens>=1&&this.queue.length){this.tokens-=1;const item=this.queue.shift();if(item.key)this.coalesced.delete(item.key);Promise.resolve().then(item.run).then(v=>item.waiters.forEach(w=>w.resolve(v)),e=>item.waiters.forEach(w=>w.reject(e)))}this.arm()}
  async execute(run,{critical=false,key=null}={}){
    for(let attempt=0;;attempt++){
      try{return await this.schedule(run,{critical,key})}catch(error){
        if(!retryable(error)||attempt>=RETRY_DELAYS_MS.length)throw error;
        const base=RETRY_DELAYS_MS[attempt],jitter=Math.round(base*(this.random()*0.4-0.2));
        await new Promise(resolve=>this.setTimer(resolve,Math.max(0,base+jitter)));
      }
    }
  }
  snapshot(){this.refill();return {rate:this.rate,capacity:this.capacity,tokens:this.tokens,queue:this.queue.length,coalesced:this.coalesced.size}}
}
