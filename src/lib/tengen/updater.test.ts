import { test } from 'node:test';
import assert from 'node:assert/strict';

import { deploy, run } from './deploy';
import {
  generateInstallerKeypair,
  installUpdate,
  sealUpdate,
  updateBinding,
} from './updater';
import {
  aggregateApprovals,
  approve,
  commit,
  dealShares,
  mintChallenge,
  type QuorumPolicy,
} from './quorum';
import { randomBytes } from './primitives';

const enc = new TextEncoder();

test('updater: FROST-signed update hands off and wipes old package', async () => {
  const oldPkg = await deploy(enc.encode('v1 source '.repeat(20)), {
    nodes: 3,
    decoys: 4,
    difficulty: 8,
    ttlMs: 500,
  });
  const newPkg = await deploy(enc.encode('v2 source, improved '.repeat(20)), {
    nodes: 4,
    decoys: 6,
    difficulty: 8,
    ttlMs: 500,
  });

  // Quorum setup.
  const { groupPk, signerKeys } = dealShares(3, [11, 22, 33, 44]);
  const policy: QuorumPolicy = { threshold: 3, windowMs: 60_000, perHourCap: 5 };

  // Installer keypair (long-term, on the installer host).
  const installer = generateInstallerKeypair();

  // Binding covers (root, installerPk).
  const binding = await updateBinding(newPkg.blobs, newPkg.entry.iv, installer.pk);
  const challenge = mintChallenge('update', binding);

  // Signing: 3-of-4 FROST flow.
  const active = signerKeys.slice(0, 3);
  const r1 = active.map((k) => commit(k));
  const commitments = r1.map((x) => x.publicCommitment);
  const partials = active.map((k, i) =>
    approve(k, r1[i]!.privateNonce, challenge, commitments, groupPk),
  );
  const sig = aggregateApprovals(commitments, partials, challenge, groupPk, policy);

  // Publisher seals.
  const bundle = await sealUpdate(newPkg, challenge, sig, installer.pk);

  // Installer applies.
  const installed = await installUpdate(oldPkg, bundle, groupPk, installer, policy);

  // Old package state zeroized.
  assert.equal(oldPkg.blobs.size, 0);
  assert.ok(oldPkg.deployKey.every((b) => b === 0));
  assert.ok(oldPkg.entry.body.every((b) => b === 0));

  // New package executes.
  const chunks: Uint8Array[] = [];
  await run(installed, async (c) => {
    chunks.push(new Uint8Array(c));
  });
  assert.equal(chunks.length, 4);
});

test('updater: bundle addressed to a different installer is rejected', async () => {
  const oldPkg = await deploy(enc.encode('v1 '.repeat(10)), {
    nodes: 3, decoys: 4, difficulty: 8, ttlMs: 500,
  });
  const newPkg = await deploy(enc.encode('v2 '.repeat(20)), {
    nodes: 3, decoys: 4, difficulty: 8, ttlMs: 500,
  });
  const { groupPk, signerKeys } = dealShares(2, [1, 2]);
  const policy: QuorumPolicy = { threshold: 2, windowMs: 60_000, perHourCap: 5 };

  const alice = generateInstallerKeypair();
  const bob = generateInstallerKeypair();

  // Signed for Alice.
  const binding = await updateBinding(newPkg.blobs, newPkg.entry.iv, alice.pk);
  const ch = mintChallenge('update', binding);
  const active = signerKeys.slice(0, 2);
  const r1 = active.map((k) => commit(k));
  const commitments = r1.map((x) => x.publicCommitment);
  const partials = active.map((k, i) =>
    approve(k, r1[i]!.privateNonce, ch, commitments, groupPk),
  );
  const sig = aggregateApprovals(commitments, partials, ch, groupPk, policy);
  const bundle = await sealUpdate(newPkg, ch, sig, alice.pk);

  // Bob tries to install.
  await assert.rejects(
    () => installUpdate(oldPkg, bundle, groupPk, bob, policy),
    /not addressed to this installer/,
  );
  assert.ok(oldPkg.blobs.size > 0, 'old package must be untouched on failed install');
});

test('updater: substituting the package body after signing is rejected', async () => {
  const oldPkg = await deploy(enc.encode('v1 '.repeat(10)), {
    nodes: 3, decoys: 4, difficulty: 8, ttlMs: 500,
  });
  const realNewPkg = await deploy(enc.encode('real v2 '.repeat(20)), {
    nodes: 3, decoys: 4, difficulty: 8, ttlMs: 500,
  });
  const fakeNewPkg = await deploy(enc.encode('fake v2 '.repeat(20)), {
    nodes: 3, decoys: 4, difficulty: 8, ttlMs: 500,
  });
  const { groupPk, signerKeys } = dealShares(2, [1, 2]);
  const policy: QuorumPolicy = { threshold: 2, windowMs: 60_000, perHourCap: 5 };
  const installer = generateInstallerKeypair();

  // Signature is for realNewPkg.
  const binding = await updateBinding(realNewPkg.blobs, realNewPkg.entry.iv, installer.pk);
  const ch = mintChallenge('update', binding);
  const active = signerKeys.slice(0, 2);
  const r1 = active.map((k) => commit(k));
  const commitments = r1.map((x) => x.publicCommitment);
  const partials = active.map((k, i) =>
    approve(k, r1[i]!.privateNonce, ch, commitments, groupPk),
  );
  const sig = aggregateApprovals(commitments, partials, ch, groupPk, policy);

  // Attacker: reuses the signature + challenge but swaps in fakeNewPkg.
  const { deployKey: _dk, ...fakeRest } = fakeNewPkg;
  void _dk;
  const malicious = {
    newPackage: fakeRest,
    challenge: ch,
    signature: sig,
    ephemeralPk: randomBytes(32),
    iv: randomBytes(12),
    wrappedDeployKey: randomBytes(48),
    installerPk: installer.pk,
  };

  await assert.rejects(
    () => installUpdate(oldPkg, malicious, groupPk, installer, policy),
    /not bound to this \(package, installer\) pair/,
  );
});
