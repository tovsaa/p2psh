// SPDX-License-Identifier: Apache-2.0
// Tests for src/server/limits.ts. Drives the rate limiter through an
// injected clock so we don't need real wall-clock waits.

import { createRateLimiter } from "../src/server/limits.js";

let failed = 0;

function ok(label: string, cond: boolean): void {
  if (cond) console.log(`ok    ${label}`);
  else {
    console.error(`FAIL  ${label}`);
    failed++;
  }
}

function throws(label: string, fn: () => unknown): void {
  try {
    fn();
    console.error(`FAIL  ${label} (expected throw)`);
    failed++;
  } catch {
    console.log(`ok    ${label}`);
  }
}

// 1. Sliding window: max attempts accepted, the next one rejected.
{
  let now = 1_000_000;
  const rl = createRateLimiter({ max: 3, windowMs: 60_000, now: () => now });
  ok("attempt 1 admitted", rl.check("a") === true);
  ok("attempt 2 admitted", rl.check("a") === true);
  ok("attempt 3 admitted", rl.check("a") === true);
  ok("attempt 4 rejected (at cap)", rl.check("a") === false);
  ok("attempt 5 rejected (still at cap)", rl.check("a") === false);
}

// 2. Independent buckets per key.
{
  let now = 1_000_000;
  const rl = createRateLimiter({ max: 2, windowMs: 60_000, now: () => now });
  ok("a:1 admitted", rl.check("a") === true);
  ok("a:2 admitted", rl.check("a") === true);
  ok("a:3 rejected", rl.check("a") === false);
  ok("b:1 admitted (different key)", rl.check("b") === true);
  ok("b:2 admitted", rl.check("b") === true);
  ok("b:3 rejected", rl.check("b") === false);
}

// 3. Window expires: oldest attempt scrolls out, capacity is freed.
{
  let now = 1_000_000;
  const rl = createRateLimiter({ max: 2, windowMs: 60_000, now: () => now });
  ok("burst attempt 1", rl.check("a") === true);
  ok("burst attempt 2", rl.check("a") === true);
  ok("burst attempt 3 rejected", rl.check("a") === false);
  // Roll the clock past the window edge: the first two attempts are still
  // inside if we move by less than windowMs.
  now += 30_000;
  ok("mid-window: still rejected", rl.check("a") === false);
  // Now scroll past both original attempts.
  now += 35_000; // total +65 s, both originals are out.
  ok("post-window: attempt admitted", rl.check("a") === true);
  ok("post-window: another admitted", rl.check("a") === true);
  ok("post-window: third rejected", rl.check("a") === false);
}

// 4. Partial expiry: only the oldest attempt scrolls out.
{
  let now = 1_000_000;
  const rl = createRateLimiter({ max: 3, windowMs: 60_000, now: () => now });
  rl.check("a"); // t=1_000_000
  now += 10_000;
  rl.check("a"); // t=1_010_000
  now += 10_000;
  rl.check("a"); // t=1_020_000  (now at cap)
  ok("at cap, 4th rejected", rl.check("a") === false);
  // Scroll past the first attempt only.
  now += 45_000; // we're at 1_065_000. Window cutoff: 1_005_000.
  // 1_000_000 is out, 1_010_000 + 1_020_000 still in => 2 in window.
  ok("one freed slot lets one through", rl.check("a") === true);
  ok("immediately back at cap", rl.check("a") === false);
}

// 5. windowOf reflects what's actually counted.
{
  let now = 1_000_000;
  const rl = createRateLimiter({ max: 5, windowMs: 60_000, now: () => now });
  rl.check("a");
  now += 100;
  rl.check("a");
  const w = rl.windowOf("a");
  ok("windowOf returns 2 entries", w.length === 2);
  ok("entries are timestamps in order", w[0] === 1_000_000 && w[1] === 1_000_100);
  ok("windowOf is a copy (mutating doesn't leak)", (() => {
    w.push(9_999);
    return rl.windowOf("a").length === 2;
  })());
}

// 6. prune() drops keys whose windows are completely empty.
{
  let now = 1_000_000;
  const rl = createRateLimiter({ max: 5, windowMs: 60_000, now: () => now });
  rl.check("a");
  rl.check("b");
  ok("two keys present", rl.windowOf("a").length === 1 && rl.windowOf("b").length === 1);
  now += 70_000; // both fall out
  rl.prune();
  ok("prune empties both keys", rl.windowOf("a").length === 0 && rl.windowOf("b").length === 0);
}

// 7. Constructor validates inputs.
{
  throws("max=0 rejected", () => createRateLimiter({ max: 0, windowMs: 1000 }));
  throws("max=-1 rejected", () => createRateLimiter({ max: -1, windowMs: 1000 }));
  throws("windowMs=0 rejected", () => createRateLimiter({ max: 1, windowMs: 0 }));
}

if (failed > 0) {
  console.error(`\n${failed} limits check(s) failed`);
  process.exit(1);
}
console.log("limits: all checks passed");
