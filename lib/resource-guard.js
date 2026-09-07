export class ResourceGuard {
  constructor({ limitBytes = 256 * 1024 ** 2, sustainedMs = 60000, clock = () => Date.now(), onFailure = () => {}, onDegradedRestart = () => {} } = {}) {
    this.limitBytes = limitBytes;
    this.sustainedMs = sustainedMs;
    this.clock = clock;
    this.onFailure = onFailure;
    this.onDegradedRestart = onDegradedRestart;
    this.overSince = null;
    this.failed = false;
  }
  observe(rssBytes, at = this.clock()) {
    if (rssBytes <= this.limitBytes) {
      this.overSince = null;
      return { state: this.failed ? 'FAILED' : 'HEALTHY', overForMs: 0 };
    }
    this.overSince ??= at;
    const overForMs = Math.max(0, at - this.overSince);
    if (!this.failed && overForMs >= this.sustainedMs) {
      this.failed = true;
      const evidence = { state: 'FAILED', reason: 'RSS_SUSTAINED_OVER_LIMIT', limitBytes: this.limitBytes, sustainedMs: this.sustainedMs, observedRssBytes: rssBytes, overForMs };
      this.onFailure(evidence);
      this.onDegradedRestart({ mode: 'CONTROLLED_DEGRADED_RESTART', reason: evidence.reason });
      return evidence;
    }
    return { state: 'PRESSURE', overForMs };
  }
}
