/** Server-wide usage limits: a token bucket (calls per minute) and a concurrency cap. */

export type Clock = () => number;

export class RateLimiter {
  private tokens: number;
  private last: number;

  constructor(
    private readonly perMinute: number,
    private readonly now: Clock = Date.now,
  ) {
    this.tokens = perMinute;
    this.last = now();
  }

  /** Take one token, or say how long until one is available. */
  tryConsume(): { ok: true } | { ok: false; retryAfterMs: number } {
    const current = this.now();
    const elapsed = Math.max(0, current - this.last);
    this.last = current;
    this.tokens = Math.min(this.perMinute, this.tokens + (elapsed * this.perMinute) / 60_000);
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return { ok: true };
    }
    const missing = 1 - this.tokens;
    return { ok: false, retryAfterMs: Math.ceil((missing * 60_000) / this.perMinute) };
  }
}

export class ConcurrencyGate {
  private active = 0;

  constructor(private readonly max: number) {}

  /** Returns a release function, or null when the server is at capacity. */
  tryAcquire(): (() => void) | null {
    if (this.active >= this.max) return null;
    this.active += 1;
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.active -= 1;
      }
    };
  }

  get inFlight(): number {
    return this.active;
  }
}
