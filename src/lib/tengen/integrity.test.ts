import { test } from 'node:test';
import assert from 'node:assert/strict';

import { deploy, run } from './deploy';
import { deploymentRoot, merkleRoot, verifyPackage } from './integrity';

const enc = new TextEncoder();

test('merkle: deterministic + order-sensitive', async () => {
  const a = enc.encode('alpha');
  const b = enc.encode('beta');
  const c = enc.encode('gamma');
  const r1 = await merkleRoot([a, b, c]);
  const r2 = await merkleRoot([a, b, c]);
  const r3 = await merkleRoot([a, c, b]);
  assert.deepEqual(r1, r2);
  assert.notDeepEqual(r1, r3);
});

test('integrity: root embedded in entry matches at runtime', async () => {
  const source = enc.encode('payload-data-'.repeat(20));
  const pkg = await deploy(source, { nodes: 4, decoys: 8, difficulty: 8, ttlMs: 500 });
  const expected = await deploymentRoot(pkg.blobs, pkg.entry.iv);
  assert.equal(await verifyPackage(pkg, expected), true);

  const chunks: Uint8Array[] = [];
  await run(pkg, async (c) => {
    chunks.push(new Uint8Array(c));
  });
  assert.equal(chunks.length, 4);
});

test('integrity: mutating any blob byte causes runtime to refuse + wipe', async () => {
  const source = enc.encode('some source '.repeat(20));
  const pkg = await deploy(source, { nodes: 3, decoys: 6, difficulty: 8, ttlMs: 500 });

  // Tamper: flip one bit in the first blob's body.
  const firstAddr = [...pkg.blobs.keys()][0]!;
  const body = pkg.blobs.get(firstAddr)!;
  body[0] = (body[0] ?? 0) ^ 0x80;

  await assert.rejects(
    () => run(pkg, async () => {}),
    /integrity check failed/,
  );
});

test('integrity: adding a decoy (forbidden mutation) also rejected', async () => {
  const source = enc.encode('more source material '.repeat(10));
  const pkg = await deploy(source, { nodes: 3, decoys: 4, difficulty: 8, ttlMs: 500 });

  // Inject a rogue blob — fake address, matching size.
  const victimSize = [...pkg.blobs.values()][0]!.length;
  const rogue = new Uint8Array(victimSize);
  crypto.getRandomValues(rogue);
  (pkg.blobs as Map<string, Uint8Array>).set('ROGUE_ADDR_NEVER_USED_BEFORE', rogue);

  await assert.rejects(
    () => run(pkg, async () => {}),
    /integrity check failed/,
  );
});

test('observer: fake probe causes runtime to wipe + throw', async () => {
  const source = enc.encode('trivial source '.repeat(8));
  const pkg = await deploy(source, { nodes: 3, decoys: 4, difficulty: 8, ttlMs: 500 });

  await assert.rejects(
    () => run(pkg, async () => {}, { isObserved: () => true }),
    /observation detected/,
  );
});
