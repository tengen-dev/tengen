import { test } from 'node:test';
import assert from 'node:assert/strict';

import { deploy, run } from './deploy';
import { obliviousFetchAll } from './integrity';
import { dkgSimulate } from './dkg';
import {
  aggregateApprovals,
  approve,
  commit,
  mintChallenge,
  type QuorumPolicy,
} from './quorum';
import {
  generateInstallerKeypair,
  installUpdate,
  sealUpdate,
  updateBinding,
} from './updater';

const enc = new TextEncoder();

test('integration: DKG → FROST-signed update → install → run', async () => {
  // 1. DKG (no trusted dealer) produces threshold Ed25519 shares.
  const signerIds = [11, 22, 33, 44, 55];
  const threshold = 3;
  const { groupPk, signerKeys } = dkgSimulate(threshold, signerIds);

  // 2. Initial deployment.
  const v1Source = enc.encode('const version = 1; '.repeat(30));
  const v1 = await deploy(v1Source, { nodes: 4, decoys: 8, difficulty: 6, ttlMs: 1000 });

  // 3. Prepare the next version.
  const v2Source = enc.encode('const version = 2; // security fix applied '.repeat(30));
  const v2Snapshot = new Uint8Array(v2Source); // deploy() will zeroize v2Source
  const v2 = await deploy(v2Source, { nodes: 5, decoys: 10, difficulty: 6, ttlMs: 1000 });

  // 4. Installer has its own long-term X25519 keypair.
  const installer = generateInstallerKeypair();

  // 5. Signers (any t=3 of 5 DKG participants) authorize the update.
  const binding = await updateBinding(v2.blobs, v2.entry.iv, installer.pk);
  const challenge = mintChallenge('update-v1-to-v2', binding);
  const policy: QuorumPolicy = { threshold, windowMs: 60_000, perHourCap: 5 };

  // Pick a non-contiguous subset to prove DKG shares are interchangeable.
  const active = [signerKeys[0]!, signerKeys[2]!, signerKeys[4]!];
  const r1 = active.map((k) => commit(k));
  const commitments = r1.map((x) => x.publicCommitment);
  const partials = active.map((k, i) =>
    approve(k, r1[i]!.privateNonce, challenge, commitments, groupPk),
  );
  const signature = aggregateApprovals(commitments, partials, challenge, groupPk, policy);

  // 6. Publisher seals the update addressed to this installer.
  const bundle = await sealUpdate(v2, challenge, signature, installer.pk);

  // 7. Installer applies.
  const installed = await installUpdate(v1, bundle, groupPk, installer, policy);

  // Old package state wiped.
  assert.equal(v1.blobs.size, 0);
  assert.ok(v1.deployKey.every((b) => b === 0));

  // 8. New package runs and recovers v2 source.
  const parts: Uint8Array[] = [];
  await run(installed, async (chunk) => {
    parts.push(new Uint8Array(chunk));
  });
  const total = parts.reduce((s, c) => s + c.length, 0);
  const joined = new Uint8Array(total);
  let off = 0;
  for (const c of parts) {
    joined.set(c, off);
    off += c.length;
  }
  assert.deepEqual(joined, v2Snapshot);
});

test('integration: obliviousFetchAll + run reconstructs source end to end', async () => {
  const source = enc.encode('full payload via oblivious fetch  '.repeat(40));
  const snapshot = new Uint8Array(source);
  const pkg = await deploy(source, { nodes: 6, decoys: 18, difficulty: 6, ttlMs: 1000 });

  // Simulate an external store: remote reads go through fetcher; runtime
  // reads from the locally materialized map.
  const externalCalls: string[] = [];
  const fetcher = async (addr: string) => {
    externalCalls.push(addr);
    return pkg.blobs.get(addr) ?? null;
  };
  const local = await obliviousFetchAll(pkg.blobs.keys(), fetcher, 0);

  // External observer sees all 24 blob addrs, in sorted order.
  const sorted = [...pkg.blobs.keys()].sort();
  assert.equal(externalCalls.length, sorted.length);
  for (let i = 0; i < sorted.length; i++) assert.equal(externalCalls[i], sorted[i]);

  const chunks: Uint8Array[] = [];
  const { runNetwork } = await import('./fragment');
  await runNetwork(
    pkg.entry,
    new Uint8Array(pkg.deployKey),
    async (addr) => local.get(addr) ?? null,
    async (chunk) => {
      chunks.push(new Uint8Array(chunk));
    },
    { blobs: local },
  );
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const joined = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    joined.set(c, off);
    off += c.length;
  }
  assert.deepEqual(joined, snapshot);
});

test('integration: 256-node round trip (stress)', async () => {
  const source = enc.encode('stress-fragmented payload. '.repeat(200));
  const snapshot = new Uint8Array(source);
  const pkg = await deploy(source, { nodes: 256, decoys: 256, difficulty: 6, ttlMs: 3000 });
  const chunks: Uint8Array[] = [];
  await run(pkg, async (c) => {
    chunks.push(new Uint8Array(c));
  });
  const joined = new Uint8Array(chunks.reduce((s, c) => s + c.length, 0));
  let off = 0;
  for (const c of chunks) {
    joined.set(c, off);
    off += c.length;
  }
  assert.deepEqual(joined, snapshot);
});
