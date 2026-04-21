import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  b64u,
  concat,
  ctEqual,
  hkdf,
  hmacSha256,
  randomBytes,
  sha256,
  zeroize,
} from './primitives';

const enc = new TextEncoder();

test('primitives: b64u round trip on empty + random + non-mult-of-3 lengths', () => {
  for (const len of [0, 1, 2, 3, 4, 5, 17, 32, 63, 64, 65]) {
    const b = randomBytes(len);
    const s = b64u.encode(b);
    const back = b64u.decode(s);
    assert.equal(back.length, b.length);
    for (let i = 0; i < b.length; i++) assert.equal(back[i], b[i]);
    assert.ok(!s.includes('=') && !s.includes('+') && !s.includes('/'));
  }
});

test('primitives: concat handles empty parts + ordering', () => {
  const out = concat(new Uint8Array([1, 2]), new Uint8Array(0), new Uint8Array([3]));
  assert.deepEqual(out, new Uint8Array([1, 2, 3]));
  assert.equal(concat().length, 0);
  assert.equal(concat(new Uint8Array(0), new Uint8Array(0)).length, 0);
});

test('primitives: ctEqual false on different lengths + unequal content', () => {
  assert.equal(ctEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false);
  assert.equal(ctEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
  assert.equal(ctEqual(new Uint8Array(0), new Uint8Array(0)), true);
  const r = randomBytes(32);
  assert.equal(ctEqual(r, r), true);
  assert.equal(ctEqual(r, new Uint8Array(r)), true);
});

test('primitives: zeroize overwrites buffer in place', () => {
  const b = new Uint8Array([1, 2, 3, 4, 5]);
  zeroize(b);
  assert.ok(b.every((x) => x === 0));
  // Multi-arg + undefined tolerance.
  const c = new Uint8Array([9, 9]);
  zeroize(c, undefined, null);
  assert.ok(c.every((x) => x === 0));
});

test('primitives: hkdf deterministic for same inputs, divergent for different salts', async () => {
  const ikm = randomBytes(32);
  const salt1 = enc.encode('salt-one');
  const salt2 = enc.encode('salt-two');
  const info = enc.encode('info');

  const a = await hkdf(ikm, salt1, info, 32);
  const b = await hkdf(ikm, salt1, info, 32);
  const c = await hkdf(ikm, salt2, info, 32);
  assert.ok(ctEqual(a, b));
  assert.ok(!ctEqual(a, c));
});

test('primitives: hkdf with different info → different output', async () => {
  const ikm = randomBytes(32);
  const salt = enc.encode('same-salt');
  const a = await hkdf(ikm, salt, enc.encode('info-a'), 32);
  const b = await hkdf(ikm, salt, enc.encode('info-b'), 32);
  assert.ok(!ctEqual(a, b));
});

test('primitives: hmac + sha256 output sizes are 32 bytes', async () => {
  const mac = await hmacSha256(randomBytes(32), enc.encode('msg'));
  assert.equal(mac.length, 32);
  const h = await sha256(enc.encode('msg'));
  assert.equal(h.length, 32);
});

test('primitives: aes-gcm round trip with + without AAD', async () => {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const pt = enc.encode('secret payload over the curve');

  const ct = await aesGcmEncrypt(key, iv, pt);
  const back = await aesGcmDecrypt(key, iv, ct);
  assert.deepEqual(back, pt);

  const aad = enc.encode('aad-v1');
  const ct2 = await aesGcmEncrypt(key, iv, pt, aad);
  const back2 = await aesGcmDecrypt(key, iv, ct2, aad);
  assert.deepEqual(back2, pt);
});

test('primitives: aes-gcm decrypt fails with wrong AAD', async () => {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const pt = enc.encode('bound-to-aad');
  const ct = await aesGcmEncrypt(key, iv, pt, enc.encode('correct'));
  await assert.rejects(() => aesGcmDecrypt(key, iv, ct, enc.encode('wrong')));
});

test('primitives: aes-gcm decrypt fails with tampered ciphertext', async () => {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const pt = enc.encode('do not tamper');
  const ct = await aesGcmEncrypt(key, iv, pt);
  ct[ct.length - 1] = (ct[ct.length - 1] ?? 0) ^ 0x01;
  await assert.rejects(() => aesGcmDecrypt(key, iv, ct));
});

test('primitives: randomBytes returns independent values of requested length', () => {
  const a = randomBytes(64);
  const b = randomBytes(64);
  assert.equal(a.length, 64);
  assert.equal(b.length, 64);
  assert.ok(!ctEqual(a, b)); // astronomically unlikely to collide
});
