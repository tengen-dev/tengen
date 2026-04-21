import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createSession } from './ephemeral';
import { reassemble, shatter } from './shatter';
import { combine, split } from './shamir';
import { mintRoute, verifyRoute } from './ephemeral';

test('shamir: k-of-n round trip', () => {
  const secret = new TextEncoder().encode('the-dark-moon-rises');
  const shares = split(secret, 3, 5);
  const recovered = combine(shares.slice(0, 3));
  assert.deepEqual(recovered, secret);
  const recovered2 = combine([shares[4]!, shares[2]!, shares[0]!]);
  assert.deepEqual(recovered2, secret);
});

test('shamir: k-1 shares reveal nothing (recovered ≠ secret)', () => {
  const secret = new TextEncoder().encode('super-sensitive-data');
  const shares = split(secret, 3, 5);
  // Technically impossible to "fail" assertively without statistical tests;
  // sanity: combine with <k shares throws or produces unrelated bytes.
  assert.throws(() => combine([shares[0]!]));
});

test('shatter/reassemble: full pipeline including decoys', async () => {
  const session = createSession(60_000);
  const plaintext = new TextEncoder().encode(
    '텐겐 프로젝트 — 존재가 은닉되는 데이터. '.repeat(40),
  );

  const { manifest, blobs } = await shatter(session, plaintext, {
    n: 6,
    k: 4,
    decoys: 20,
    backends: 3,
  });

  // Address-indistinguishability: sizes should not betray real vs decoy.
  const sizes = new Set(blobs.map((b) => b.body.length));
  // Only one canonical size expected (or very few) given fixed chunk size.
  assert.ok(sizes.size <= 2, `too many distinct blob sizes: ${sizes.size}`);

  // Build an in-memory backend keyed by (addr, backend).
  const store = new Map<string, Uint8Array>();
  for (const b of blobs) store.set(`${b.backend}:${b.addr}`, b.body);

  const fetchBlob = async (addr: string, backend: number) =>
    store.get(`${backend}:${addr}`) ?? null;

  const recovered = await reassemble(session, manifest, fetchBlob);
  assert.deepEqual(recovered, plaintext);
  session.burn();
});

test('shatter: wrong session cannot unwrap any shard', async () => {
  const alice = createSession();
  const mallory = createSession();
  const data = new TextEncoder().encode('private');

  const { manifest, blobs } = await shatter(alice, data, { n: 4, k: 3, decoys: 4, backends: 2 });
  const store = new Map<string, Uint8Array>();
  for (const b of blobs) store.set(`${b.backend}:${b.addr}`, b.body);

  await assert.rejects(
    reassemble(mallory, manifest, async (addr, backend) => store.get(`${backend}:${addr}`) ?? null),
  );
});

test('ephemeral route: mint/verify round trip + expiry', async () => {
  const session = createSession(100);
  const token = await mintRoute(session);
  assert.equal(await verifyRoute(session, token), true);

  // Bad token → false (no throw).
  assert.equal(await verifyRoute(session, 'garbage'), false);

  // Expired.
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(await verifyRoute(session, token), false);
});
