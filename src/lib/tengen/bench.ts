/**
 * Tengen benchmarks.
 *
 *   Measures wall-clock and (where meaningful) bandwidth characteristics
 *   for the primary operations. Print-only; no assertions.
 *
 *   This is not a replacement for a real performance lab — it runs on
 *   whatever machine invoked it, single-threaded, with V8 JIT warming up
 *   as it goes. Treat results as directional.
 */

import { aggregate, commit, dealGroupKey, sign, verify } from './frost';
import { deploy, run } from './deploy';
import { randomBytes } from './primitives';
import { obliviousFetchAll } from './integrity';

interface Row {
  label: string;
  n?: number;
  value: string;
}

const rows: Row[] = [];

const record = (label: string, value: string, n?: number): void => {
  rows.push({ label, value, ...(n !== undefined ? { n } : {}) });
};

const timeMs = async <T>(fn: () => Promise<T> | T): Promise<[T, number]> => {
  const t0 = performance.now();
  const v = await fn();
  return [v, performance.now() - t0];
};

const fmt = (ms: number): string =>
  ms < 1 ? `${(ms * 1000).toFixed(0)}µs` : ms < 1000 ? `${ms.toFixed(1)}ms` : `${(ms / 1000).toFixed(2)}s`;

// ---- deploy / run timing vs N -------------------------------------------

const benchDeployRun = async (): Promise<void> => {
  const source = randomBytes(8192);
  for (const n of [10, 100, 500, 1000]) {
    const decoys = n * 2;
    const [, dMs] = await timeMs(() =>
      deploy(new Uint8Array(source), { nodes: n, decoys, difficulty: 6, ttlMs: 2_000 }),
    );
    record(`deploy`, fmt(dMs), n);

    // Fresh pkg for run timing (deploy above consumed one).
    const pkg = await deploy(new Uint8Array(source), {
      nodes: n, decoys, difficulty: 6, ttlMs: 2_000,
    });
    const [, rMs] = await timeMs(() => run(pkg, async () => {}));
    record(`run`, fmt(rMs), n);
  }
};

// ---- FROST sign+aggregate+verify vs threshold ----------------------------

const benchFrost = async (): Promise<void> => {
  for (const t of [2, 3, 5, 7]) {
    const n = t + 2;
    const ids = Array.from({ length: n }, (_, i) => i + 1);
    const { groupPk, signerKeys } = dealGroupKey(t, ids);
    const active = signerKeys.slice(0, t);
    const msg = randomBytes(64);

    // Round 1 (commit) is local to each signer.
    const [r1, commitMs] = await timeMs(() => active.map((k) => commit(k)));
    record(`frost commit × ${t}`, fmt(commitMs), t);

    const commitments = r1.map((x) => x.publicCommitment);
    const [partials, signMs] = await timeMs(() =>
      active.map((k, i) => sign(k, r1[i]!.privateNonce, msg, commitments, groupPk)),
    );
    record(`frost sign × ${t}`, fmt(signMs), t);

    const [sig, aggMs] = await timeMs(() => aggregate(commitments, partials, msg, groupPk));
    record(`frost aggregate`, fmt(aggMs), t);

    const [, verMs] = await timeMs(() => verify(sig, msg, groupPk));
    record(`frost verify`, fmt(verMs), t);
  }
};

// ---- oblivious-fetch bandwidth multiplier -------------------------------

const benchOblivious = async (): Promise<void> => {
  const source = randomBytes(4096);
  const cases: Array<[number, number]> = [[5, 5], [5, 15], [5, 45], [10, 90]];
  for (const [nodes, decoys] of cases) {
    const pkg = await deploy(new Uint8Array(source), {
      nodes, decoys, difficulty: 6, ttlMs: 2_000,
    });
    const requests: string[] = [];
    const fetcher = async (addr: string) => {
      requests.push(addr);
      return pkg.blobs.get(addr) ?? null;
    };
    const [, t] = await timeMs(() => obliviousFetchAll(pkg.blobs.keys(), fetcher, 0));
    const ratio = requests.length / nodes;
    record(
      `oblivious fetch (${nodes} real, ${decoys} decoy)`,
      `${requests.length} reqs  ×${ratio.toFixed(1)}  ${fmt(t)}`,
      nodes,
    );
  }
};

// ---- driver -------------------------------------------------------------

const main = async (): Promise<void> => {
  console.log('tengen bench · warming up (single-threaded, JIT)…\n');
  await benchDeployRun();
  await benchFrost();
  await benchOblivious();

  const bar = '─'.repeat(72);
  console.log(bar);
  console.log('  BENCH REPORT');
  console.log(bar);
  const maxLabel = Math.max(...rows.map((r) => r.label.length));
  for (const r of rows) {
    const label = r.label.padEnd(maxLabel, ' ');
    const n = r.n !== undefined ? `n=${String(r.n).padStart(5)}` : ' '.repeat(7);
    console.log(`  ${label}  ${n}  ${r.value}`);
  }
  console.log(bar + '\n');
};

main().catch((e) => {
  console.error('bench: fatal', e);
  process.exitCode = 1;
});
