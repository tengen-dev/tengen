import { test } from 'node:test';
import assert from 'node:assert/strict';

import { dkgFinalize, dkgShareFor, dkgStart, dkgAcceptShare, dkgSimulate } from './dkg';
import { aggregate, commit, sign, verify } from './frost';
import { randomBytes } from './primitives';

const enc = new TextEncoder();

test('dkg: simulation produces signer keys that work with FROST sign/verify', () => {
  const ids = [11, 22, 33, 44];
  const t = 3;
  const { groupPk, signerKeys } = dkgSimulate(t, ids);
  assert.equal(signerKeys.length, 4);
  assert.equal(groupPk.threshold, t);

  // Use 3 of the 4 DKG shares to produce a FROST signature.
  const active = signerKeys.slice(0, 3);
  const r1 = active.map((k) => commit(k));
  const commitments = r1.map((x) => x.publicCommitment);
  const msg = enc.encode('dkg-cross-compat');
  const partials = active.map((k, i) => sign(k, r1[i]!.privateNonce, msg, commitments, groupPk));
  const sig = aggregate(commitments, partials, msg, groupPk);
  assert.equal(verify(sig, msg, groupPk), true);
});

test('dkg: invalid share fails verification', () => {
  const alice = dkgStart(1, 2);
  const bob = dkgStart(2, 2);

  const shareAliceToBob = dkgShareFor(alice, 2);
  const okReal = dkgAcceptShare(bob, 1, shareAliceToBob, alice.commitments);
  assert.equal(okReal, true);

  const bogus = shareAliceToBob + 1n;
  const bob2 = dkgStart(2, 2);
  const okBogus = dkgAcceptShare(bob2, 1, bogus, alice.commitments);
  assert.equal(okBogus, false);
});

test('dkg: missing peer share aborts finalize', () => {
  const ids = [1, 2, 3];
  const locals = ids.map((id) => dkgStart(id, 2));
  // Exchange all shares EXCEPT no-one sends to participant 3.
  for (const s of locals) {
    for (const r of locals) {
      if (s.id === r.id || r.id === 3) continue;
      dkgAcceptShare(r, s.id, dkgShareFor(s, r.id), s.commitments);
    }
  }
  // Participant 3 finalizing → should throw (missing shares from 1 and 2).
  assert.throws(() => dkgFinalize(locals[2]!, ids));
});

test('dkg: any t-subset of DKG shares produces a verifying signature', () => {
  const ids = [1, 2, 3, 4, 5];
  const t = 3;
  const { groupPk, signerKeys } = dkgSimulate(t, ids);

  for (const subset of [
    signerKeys.slice(0, 3),
    [signerKeys[0]!, signerKeys[2]!, signerKeys[4]!],
    [signerKeys[1]!, signerKeys[3]!, signerKeys[4]!],
  ]) {
    const r1 = subset.map((k) => commit(k));
    const commitments = r1.map((x) => x.publicCommitment);
    const msg = randomBytes(24);
    const partials = subset.map((k, i) => sign(k, r1[i]!.privateNonce, msg, commitments, groupPk));
    const sig = aggregate(commitments, partials, msg, groupPk);
    assert.equal(verify(sig, msg, groupPk), true);
  }
});
