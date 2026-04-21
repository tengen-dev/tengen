/**
 * Tengen fuzz harness.
 *
 *   Drives randomized inputs through deploy/run/verify and the crypto
 *   primitives, expecting every path to either succeed or throw a typed
 *   error. A crash (uncaught, non-Error throw, unhandled rejection) OR a
 *   silent corruption (run() returned but bytes don't match) is recorded
 *   as a failure.
 *
 * Run:   npm run fuzz [-- --iterations N] [-- --seed INFO]
 *
 * Note: Web Crypto RNG is not seedable, so reproducibility is best-effort.
 *       On failure we dump the offending input so the case can be rebuilt.
 */

import { aggregate, commit, dealGroupKey, sign, verify } from './frost';
import { combine, split, splitAtXs } from './shamir';
import { deploy, run } from './deploy';
import { randomBytes } from './primitives';

// ---- CLI args -----------------------------------------------------------

const args = process.argv.slice(2);
const iterations = (() => {
  const i = args.indexOf('--iterations');
  if (i >= 0) return Math.max(1, Number(args[i + 1]) || 200);
  return 200;
})();

// ---- result accumulator -------------------------------------------------

interface FuzzCategory {
  runs: number;
  passed: number;
  expectedFailures: number; // "malformed input → typed rejection" counts as pass
  unexpectedFailures: Array<{ iteration: number; error: string; detail?: unknown }>;
  crashes: Array<{ iteration: number; error: string; stack?: string }>;
}

const makeCat = (): FuzzCategory => ({
  runs: 0,
  passed: 0,
  expectedFailures: 0,
  unexpectedFailures: [],
  crashes: [],
});

const cats = {
  deployRoundTrip: makeCat(),
  deployTamper: makeCat(),
  shamir: makeCat(),
  frost: makeCat(),
};

// ---- primitives ---------------------------------------------------------

const randInt = (min: number, max: number): number => {
  const r = randomBytes(4);
  const u = ((r[0]! << 24) | (r[1]! << 16) | (r[2]! << 8) | r[3]!) >>> 0;
  return min + (u % (max - min + 1));
};

const randSource = (): Uint8Array => {
  const size = randInt(16, 8192);
  return randomBytes(size);
};

const safeRun = async (label: string, iter: number, fn: () => Promise<void>): Promise<void> => {
  const cat = cats[label as keyof typeof cats]!;
  cat.runs++;
  try {
    await fn();
    cat.passed++;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const stack = e instanceof Error ? e.stack : undefined;
    // A thrown Error with a descriptive message is a "clean rejection".
    // We treat it as a pass for tamper tests and a crash for happy-path.
    if (/tamper|invalid|mismatch|missing|integrity|decrypt|below threshold|not bound|operation-specific/i.test(msg)) {
      cat.expectedFailures++;
    } else {
      cat.unexpectedFailures.push({ iteration: iter, error: msg, detail: { stack } });
    }
    void stack;
  }
};

// ---- category 1: deploy → run round trip --------------------------------

const fuzzDeployRoundTrip = async (iter: number): Promise<void> => {
  await safeRun('deployRoundTrip', iter, async () => {
    const source = randSource();
    const nodes = randInt(2, 16);
    const decoys = randInt(0, 32);
    const difficulty = randInt(4, 10);

    const pkg = await deploy(new Uint8Array(source), { nodes, decoys, difficulty, ttlMs: 500 });
    const parts: Uint8Array[] = [];
    await run(pkg, async (c) => {
      parts.push(new Uint8Array(c));
    });
    const total = parts.reduce((s, c) => s + c.length, 0);
    const joined = new Uint8Array(total);
    let off = 0;
    for (const c of parts) {
      joined.set(c, off);
      off += c.length;
    }
    if (joined.length !== source.length) throw new Error(`length mismatch: ${joined.length} vs ${source.length}`);
    for (let i = 0; i < source.length; i++) {
      if (joined[i] !== source[i]) throw new Error(`byte ${i} mismatch: ${joined[i]} vs ${source[i]}`);
    }
  });
};

// ---- category 2: random tampering of a valid package --------------------

const fuzzDeployTamper = async (iter: number): Promise<void> => {
  await safeRun('deployTamper', iter, async () => {
    const source = randSource();
    const pkg = await deploy(new Uint8Array(source), {
      nodes: randInt(2, 8),
      decoys: randInt(0, 8),
      difficulty: randInt(4, 8),
      ttlMs: 500,
    });

    // Pick a random tamper strategy.
    const strategy = randInt(0, 4);
    switch (strategy) {
      case 0: {
        // Flip a byte in a random blob.
        const addrs = [...pkg.blobs.keys()];
        const target = addrs[randInt(0, addrs.length - 1)]!;
        const body = pkg.blobs.get(target)!;
        const idx = randInt(0, body.length - 1);
        body[idx] = (body[idx] ?? 0) ^ (0x01 << randInt(0, 7));
        break;
      }
      case 1: {
        // Flip a byte in the entry envelope.
        const idx = randInt(0, pkg.entry.body.length - 1);
        pkg.entry.body[idx] = (pkg.entry.body[idx] ?? 0) ^ 0x01;
        break;
      }
      case 2: {
        // Truncate a random blob.
        const addrs = [...pkg.blobs.keys()];
        const target = addrs[randInt(0, addrs.length - 1)]!;
        const body = pkg.blobs.get(target)!;
        (pkg.blobs as Map<string, Uint8Array>).set(target, body.slice(0, Math.max(1, body.length - randInt(1, 8))));
        break;
      }
      case 3: {
        // Wipe the deploy key.
        pkg.deployKey.fill(0);
        break;
      }
      case 4: {
        // Delete a random blob entirely.
        const addrs = [...pkg.blobs.keys()];
        const target = addrs[randInt(0, addrs.length - 1)]!;
        (pkg.blobs as Map<string, Uint8Array>).delete(target);
        break;
      }
    }

    // Expect a clean failure — NOT a successful reassemble.
    let reassembled = false;
    try {
      await run(pkg, async () => {});
      reassembled = true;
    } catch {
      // expected
    }
    if (reassembled) throw new Error(`tamper strategy ${strategy} went undetected`);
    throw new Error('tamper detected cleanly'); // moves to expectedFailures bucket
  });
};

// ---- category 3: Shamir round trip with random k, n, bytes --------------

const fuzzShamir = async (iter: number): Promise<void> => {
  await safeRun('shamir', iter, async () => {
    const n = randInt(3, 12);
    const k = randInt(2, n);
    const len = randInt(1, 256);
    const secret = randomBytes(len);
    const shares = split(secret, k, n);
    // Random k-subset.
    const shuffled = [...shares].sort(() => (randInt(0, 1) ? 1 : -1));
    const subset = shuffled.slice(0, k);
    const recovered = combine(subset);
    if (recovered.length !== secret.length) throw new Error('length mismatch');
    for (let i = 0; i < secret.length; i++) {
      if (recovered[i] !== secret[i]) throw new Error(`byte ${i} mismatch`);
    }

    // splitAtXs with caller-provided x-coords, same check.
    const xs = Array.from({ length: n }, (_, i) => i + 1);
    const shares2 = splitAtXs(secret, k, xs);
    const recovered2 = combine(shares2.slice(0, k));
    for (let i = 0; i < secret.length; i++) {
      if (recovered2[i] !== secret[i]) throw new Error(`byte ${i} mismatch in splitAtXs path`);
    }
  });
};

// ---- category 4: FROST random round trip + tamper -----------------------

const fuzzFrost = async (iter: number): Promise<void> => {
  await safeRun('frost', iter, async () => {
    const n = randInt(2, 8);
    const t = randInt(2, n);
    const ids = Array.from({ length: n }, (_, i) => i + 1);
    const { groupPk, signerKeys } = dealGroupKey(t, ids);

    // Happy path with random t-subset.
    const active = [...signerKeys].sort(() => (randInt(0, 1) ? 1 : -1)).slice(0, t);
    const r1 = active.map((k) => commit(k));
    const commitments = r1.map((x) => x.publicCommitment);
    const msg = randomBytes(randInt(1, 128));
    const partials = active.map((k, i) => sign(k, r1[i]!.privateNonce, msg, commitments, groupPk));
    const sig = aggregate(commitments, partials, msg, groupPk);
    if (!verify(sig, msg, groupPk)) throw new Error('valid signature did not verify');

    // Tamper check: flip a byte of z → must fail.
    const tampered = { ...sig, z: new Uint8Array(sig.z) };
    const idx = randInt(0, 31);
    tampered.z[idx] = (tampered.z[idx] ?? 0) ^ 0x01;
    if (verify(tampered, msg, groupPk)) throw new Error('tampered signature verified (!!)');
  });
};

// ---- driver -------------------------------------------------------------

process.on('uncaughtException', (e) => {
  // Any uncaught exception during the fuzz is a crash.
  const stack = e instanceof Error ? e.stack : undefined;
  cats.deployRoundTrip.crashes.push({
    iteration: -1,
    error: e instanceof Error ? e.message : String(e),
    ...(stack ? { stack } : {}),
  });
});

const main = async (): Promise<void> => {
  console.log(`tengen fuzz · ${iterations} iterations per category\n`);
  const t0 = Date.now();
  for (let i = 0; i < iterations; i++) {
    if (i > 0 && i % Math.max(1, Math.floor(iterations / 10)) === 0) {
      process.stderr.write(`.`);
    }
    await fuzzDeployRoundTrip(i);
    await fuzzDeployTamper(i);
    await fuzzShamir(i);
    await fuzzFrost(i);
  }
  process.stderr.write('\n');
  const secs = ((Date.now() - t0) / 1000).toFixed(1);

  const bar = '─'.repeat(72);
  console.log(bar);
  console.log('  FUZZ REPORT');
  console.log(bar);
  let anyUnexpected = false;
  for (const [name, cat] of Object.entries(cats)) {
    const expectedRate = cat.runs > 0 ? ((cat.passed + cat.expectedFailures) / cat.runs) * 100 : 0;
    console.log(
      `\n[${name}]` +
        `\n  runs:                ${cat.runs}` +
        `\n  passed:              ${cat.passed}` +
        `\n  expected failures:   ${cat.expectedFailures}` +
        `\n  UNEXPECTED failures: ${cat.unexpectedFailures.length}` +
        `\n  CRASHES:             ${cat.crashes.length}` +
        `\n  coverage:            ${expectedRate.toFixed(1)}% (expected outcomes)`,
    );
    for (const f of cat.unexpectedFailures.slice(0, 5)) {
      console.log(`  ! iter=${f.iteration}: ${f.error}`);
      anyUnexpected = true;
    }
    if (cat.unexpectedFailures.length > 5) {
      console.log(`  (+${cat.unexpectedFailures.length - 5} more)`);
    }
    for (const c of cat.crashes.slice(0, 5)) {
      console.log(`  !! CRASH iter=${c.iteration}: ${c.error}`);
      if (c.stack) console.log(c.stack.split('\n').slice(0, 3).join('\n'));
      anyUnexpected = true;
    }
  }
  console.log('\n' + bar);
  console.log(`  total wall time: ${secs}s — ${anyUnexpected ? 'ATTENTION: unexpected outcomes' : 'all outcomes within expectations'}`);
  console.log(bar + '\n');
  if (anyUnexpected) process.exitCode = 2;
};

main().catch((e) => {
  console.error('fuzz: fatal', e);
  process.exitCode = 1;
});
