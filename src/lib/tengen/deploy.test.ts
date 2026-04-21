import { test } from 'node:test';
import assert from 'node:assert/strict';

import { deploy, run } from './deploy';
import { randomBytes } from './primitives';

const enc = new TextEncoder();

test('deploy → run: reconstructs source exactly through fragmented chain', async () => {
  const source = enc.encode(
    'const tengen = () => { return 42; };\n' +
    'export function main() { return tengen() + 1; }\n' +
    '// trailing comment block '.repeat(20),
  );
  const original = new Uint8Array(source); // clone for assertion

  const pkg = await deploy(source, { nodes: 8, decoys: 24, difficulty: 10, ttlMs: 500 });

  assert.equal(pkg.realCount, 8);
  assert.equal(pkg.decoyCount, 24);
  assert.equal(pkg.blobs.size, 8 + 24);

  const reconstructed: Uint8Array[] = new Array(8);
  await run(pkg, async (chunk, i) => {
    // Runtime zero-fills the live chunk buffer after callback returns, so
    // consumers that want to retain data must copy.
    reconstructed[i] = new Uint8Array(chunk);
  });

  const joined = new Uint8Array(reconstructed.reduce((s, c) => s + c.length, 0));
  let off = 0;
  for (const c of reconstructed) {
    joined.set(c, off);
    off += c.length;
  }
  assert.deepEqual(joined, original);
});

test('deploy: wrong deploy key cannot open entry envelope', async () => {
  const source = enc.encode('payload');
  const pkg = await deploy(source, { nodes: 3, decoys: 5, difficulty: 8, ttlMs: 500 });
  const bogus = randomBytes(32);
  await assert.rejects(() =>
    run({ ...pkg, deployKey: bogus }, async () => {}),
  );
});

test('deploy: shuffled/decoy-padded blobs are indistinguishable by size', async () => {
  const source = enc.encode('abcdefghijklmnop'.repeat(64));
  const pkg = await deploy(source, { nodes: 4, decoys: 12, difficulty: 8, ttlMs: 500 });
  const sizes = new Set([...pkg.blobs.values()].map((b) => b.length));
  assert.equal(sizes.size, 1, `expected uniform blob size, got ${[...sizes]}`);
});
