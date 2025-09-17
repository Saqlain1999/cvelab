type ServiceName = string;

class TokenBucket {
  private capacity: number;
  private tokens: number;
  private refillRatePerSec: number;
  private lastRefill: number;

  constructor(refillPerSec: number, burst: number) {
    this.capacity = Math.max(1, burst);
    this.tokens = this.capacity;
    this.refillRatePerSec = Math.max(0.1, refillPerSec);
    this.lastRefill = Date.now();
  }

  private refill() {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefill) / 1000;
    if (elapsedSec <= 0) return;
    const add = elapsedSec * this.refillRatePerSec;
    this.tokens = Math.min(this.capacity, this.tokens + add);
    this.lastRefill = now;
  }

  async consume(): Promise<void> {
    // simple wait loop; for server-side usage small overhead is fine
    // try immediate, otherwise wait until a token becomes available
    while (true) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.max(50, Math.ceil(1000 / this.refillRatePerSec));
      await new Promise(r => setTimeout(r, waitMs));
    }
  }
}

const limiters = new Map<ServiceName, TokenBucket>();

function getNumbersFromEnv(prefix: string, defaults: { rps: number; burst: number }) {
  const rps = Number(process.env[`${prefix}_RPS`]) || defaults.rps;
  const burst = Number(process.env[`${prefix}_BURST`]) || defaults.burst;
  return { rps, burst };
}

export function getLimiter(service: ServiceName): TokenBucket {
  if (limiters.has(service)) return limiters.get(service)!;

  const def = getNumbersFromEnv('RATE_LIMIT_DEFAULT', { rps: 2, burst: 5 });
  // per-service overrides
  const svcKey = service.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  const overrides = getNumbersFromEnv(`RL_${svcKey}`, def);
  const limiter = new TokenBucket(overrides.rps, overrides.burst);
  limiters.set(service, limiter);
  return limiter;
}

export async function rateLimit(service: ServiceName): Promise<void> {
  const limiter = getLimiter(service);
  await limiter.consume();
}


