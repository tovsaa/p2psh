// SPDX-License-Identifier: Apache-2.0
// Tiny per-key sliding-window rate limiter, factored out of main.ts so
// tests can drive it deterministically through an injected clock.
//
// Storage: one array of millisecond timestamps per key. Pruned on read,
// so memory is O(active keys × max). For the server's use (one key per
// distinct peer Nym address) this is bounded by peer churn × max ~
// 10 numbers per peer, dropped on the next prune call.

export interface RateLimiter {
  /** Returns true and records the attempt if under the cap; false otherwise. */
  check(key: string): boolean;
  /** Manual purge — drops any key whose entire window has fallen out of range. */
  prune(): void;
  /** Test seam for current window contents under a key. */
  windowOf(key: string): number[];
}

export interface RateLimiterOptions {
  /** Max attempts per key per windowMs. */
  max: number;
  /** Window length in milliseconds. */
  windowMs: number;
  /** Clock function. Defaults to Date.now; tests pass a controllable stub. */
  now?: () => number;
}

export function createRateLimiter(opts: RateLimiterOptions): RateLimiter {
  if (opts.max <= 0) throw new Error("rate limiter: max must be > 0");
  if (opts.windowMs <= 0) throw new Error("rate limiter: windowMs must be > 0");
  const now = opts.now ?? ((): number => Date.now());
  const buckets = new Map<string, number[]>();

  const pruneKey = (key: string, t: number): number[] => {
    const cutoff = t - opts.windowMs;
    const arr = (buckets.get(key) ?? []).filter((ts) => ts >= cutoff);
    buckets.set(key, arr);
    return arr;
  };

  return {
    check(key: string): boolean {
      const t = now();
      const arr = pruneKey(key, t);
      if (arr.length >= opts.max) return false;
      arr.push(t);
      return true;
    },
    prune(): void {
      const t = now();
      for (const key of buckets.keys()) {
        const arr = pruneKey(key, t);
        if (arr.length === 0) buckets.delete(key);
      }
    },
    windowOf(key: string): number[] {
      return [...(buckets.get(key) ?? [])];
    },
  };
}
