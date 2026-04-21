import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  deriveNextKey,
  digestExecution,
  mintEdgeSecret,
  openChannel,
  solve,
  verify,
} from './channel';
import { ctEqual, randomBytes } from './primitives';

test('channel: solve produces a nonce that verify accepts', async () => {
  const s = mintEdgeSecret();
  const d = await digestExecution(new Uint8Array([1, 2, 3, 4]));
  const puzzle = { difficulty: 8, ttlMs: 1 };
  const sol = await solve(s, d, puzzle);
  assert.equal(await verify(s, d, sol, puzzle), true);
});

test('channel: verify rejects solution under wrong edge secret', async () => {
  const sa = mintEdgeSecret();
  const sb = mintEdgeSecret();
  const d = await digestExecution(new Uint8Array([7, 8, 9]));
  const puzzle = { difficulty: 8, ttlMs: 1 };
  const sol = await solve(sa, d, puzzle);
  assert.equal(await verify(sb, d, sol, puzzle), false);
});

test('channel: verify rejects tampered nonce', async () => {
  const s = mintEdgeSecret();
  const d = await digestExecution(randomBytes(16));
  const puzzle = { difficulty: 8, ttlMs: 1 };
  const sol = await solve(s, d, puzzle);
  const tampered = { ...sol, nonce: new Uint8Array(sol.nonce) };
  tampered.nonce[0] = (tampered.nonce[0] ?? 0) ^ 0x01;
  assert.equal(await verify(s, d, tampered, puzzle), false);
});

test('channel: openChannel zeroizes the key after TTL', async () => {
  const key = new Uint8Array(32);
  key.fill(7);
  const ch = openChannel(key, 20);
  assert.ok(ch.use() !== null);
  await new Promise((r) => setTimeout(r, 60));
  assert.equal(ch.use(), null);
  assert.ok(key.every((b) => b === 0), 'key must be zeroized after expiry');
});

test('channel: openChannel close is idempotent', () => {
  const key = new Uint8Array(32);
  key.fill(5);
  const ch = openChannel(key, 10_000);
  ch.close();
  ch.close();
  ch.close();
  assert.equal(ch.use(), null);
  assert.ok(key.every((b) => b === 0));
});

test('channel: deriveNextKey deterministic + input-sensitive', async () => {
  const s = mintEdgeSecret();
  const d = await digestExecution(new Uint8Array([1]));
  const sol = await solve(s, d, { difficulty: 6, ttlMs: 1 });
  const k1 = await deriveNextKey(s, d, sol);
  const k2 = await deriveNextKey(s, d, sol);
  assert.ok(ctEqual(k1, k2));
  const d2 = await digestExecution(new Uint8Array([2]));
  const sol2 = await solve(s, d2, { difficulty: 6, ttlMs: 1 });
  const k3 = await deriveNextKey(s, d2, sol2);
  assert.ok(!ctEqual(k1, k3));
});

test('channel: digestExecution is deterministic + collision-resistant across tiny perturbations', async () => {
  const a = await digestExecution(new Uint8Array([1, 2, 3]));
  const b = await digestExecution(new Uint8Array([1, 2, 3]));
  const c = await digestExecution(new Uint8Array([1, 2, 4]));
  assert.ok(ctEqual(a, b));
  assert.ok(!ctEqual(a, c));
});
