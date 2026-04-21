import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createSession } from './ephemeral';
import { reassemble, shatter, sealManifest, openManifest } from './shatter';
import { combine, split, splitAtXs } from './shamir';
import { mintRoute, verifyRoute } from './ephemeral';
import { ctEqual, randomBytes } from './primitives';

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

test('shamir: duplicate x rejected in splitAtXs', () => {
  const secret = new Uint8Array([1, 2, 3, 4]);
  assert.throws(() => splitAtXs(secret, 2, [5, 5, 6]), /duplicate/);
});

test('shamir: x=0 rejected', () => {
  const secret = new Uint8Array([9, 9, 9]);
  assert.throws(() => splitAtXs(secret, 2, [0, 1, 2]), /\[1,255\]/);
});

test('shamir: property — 20 random k-subsets all recover the secret', () => {
  const secret = new TextEncoder().encode('a moderately long secret for many subsets');
  const n = 7;
  const k = 4;
  const shares = split(secret, k, n);
  for (let trial = 0; trial < 20; trial++) {
    // Random permutation, take first k.
    const perm = shares.slice().sort(() => (Math.random() < 0.5 ? 1 : -1));
    const recovered = combine(perm.slice(0, k));
    assert.deepEqual(recovered, secret);
  }
});

test('shatter: k=n requires every shard to reassemble', async () => {
  const session = createSession();
  const data = new TextEncoder().encode('exact-count reassembly');
  const { manifest, blobs } = await shatter(session, data, {
    n: 3, k: 3, decoys: 4, backends: 3,
  });
  const store = new Map<string, Uint8Array>();
  for (const b of blobs) store.set(`${b.backend}:${b.addr}`, b.body);
  const fetched = await reassemble(session, manifest, async (addr, backend) =>
    store.get(`${backend}:${addr}`) ?? null);
  assert.deepEqual(fetched, data);
  session.burn();
});

test('shatter: single-byte payload round-trips', async () => {
  const session = createSession();
  const data = new Uint8Array([0x2a]); // 42
  const { manifest, blobs } = await shatter(session, data, {
    n: 2, k: 2, decoys: 3, backends: 3,
  });
  const store = new Map<string, Uint8Array>();
  for (const b of blobs) store.set(`${b.backend}:${b.addr}`, b.body);
  const fetched = await reassemble(session, manifest, async (addr, backend) =>
    store.get(`${backend}:${addr}`) ?? null);
  assert.deepEqual(fetched, data);
  session.burn();
});

test('shatter: manifest envelope round-trip (sealManifest / openManifest)', async () => {
  const session = createSession();
  const data = randomBytes(256);
  const { manifest } = await shatter(session, data, { n: 4, k: 3, decoys: 2, backends: 2 });
  const clientKey = randomBytes(32);
  const env = await sealManifest(manifest, clientKey);
  const opened = await openManifest(env, clientKey);
  assert.equal(opened.k, manifest.k);
  assert.equal(opened.n, manifest.n);
  assert.equal(opened.size, manifest.size);
  assert.ok(ctEqual(opened.iv, manifest.iv));
  for (let i = 0; i < manifest.salts.length; i++) {
    assert.ok(ctEqual(opened.salts[i]!, manifest.salts[i]!));
  }
});

test('shatter: manifest envelope with wrong client key fails to open', async () => {
  const session = createSession();
  const data = randomBytes(128);
  const { manifest } = await shatter(session, data, { n: 3, k: 2, decoys: 2, backends: 1 });
  const env = await sealManifest(manifest, randomBytes(32));
  await assert.rejects(() => openManifest(env, randomBytes(32)));
});

test('ephemeral: session.burn is idempotent + blanks secret', () => {
  const session = createSession(1_000);
  const secretBefore = new Uint8Array(session.secret);
  assert.ok(!ctEqual(secretBefore, new Uint8Array(32)));
  session.burn();
  assert.ok(session.secret.every((b) => b === 0));
  session.burn(); // second call → no throw, no effect
  assert.ok(session.secret.every((b) => b === 0));
});
