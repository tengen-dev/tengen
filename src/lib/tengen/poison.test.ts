import { test } from 'node:test';
import assert from 'node:assert/strict';

import { randomBytes } from './primitives';
import { forge, forgeBatch } from './poison';
import {
  aggregateApprovals,
  approve,
  commit,
  dealShares,
  mintChallenge,
  verifyApproval,
  type QuorumPolicy,
} from './quorum';
import { detect, minLatencyMs, createNode, guardNode } from './lightspeed';

test('poison: forged record is stable, signed, and carries tripwires', async () => {
  const key = randomBytes(32);
  const r = await forge({ collectorDomain: 'canary.example', poisonKey: key });
  assert.equal(typeof r.id, 'string');
  assert.equal(typeof r.signature, 'string');
  assert.ok((r.fields.email as any).value.includes('@canary.example'));
  assert.ok((r.fields.api_token as any).value.startsWith('sk_live_'));
  const r2 = await forge({ collectorDomain: 'canary.example', poisonKey: key });
  assert.notEqual(r.id, r2.id);
});

test('poison: batch produces N distinct records', async () => {
  const key = randomBytes(32);
  const batch = await forgeBatch({ collectorDomain: 'canary.example', poisonKey: key }, 5);
  assert.equal(batch.length, 5);
  assert.equal(new Set(batch.map((x) => x.id)).size, 5);
});

test('quorum (FROST): t-of-n produces a verifying signature', () => {
  const { groupPk, signerKeys } = dealShares(3, [11, 22, 33, 44]);
  const policy: QuorumPolicy = { threshold: 3, windowMs: 60_000, perHourCap: 5 };
  const ch = mintChallenge('open-vault', randomBytes(32));

  const active = signerKeys.slice(0, 3);
  const r1 = active.map((k) => commit(k));
  const commitments = r1.map((x) => x.publicCommitment);
  const partials = active.map((k, i) =>
    approve(k, r1[i]!.privateNonce, ch, commitments, groupPk),
  );
  const sig = aggregateApprovals(commitments, partials, ch, groupPk, policy);
  assert.equal(verifyApproval(sig, ch, groupPk, policy), true);
});

test('quorum (FROST): partial signature from wrong message fails to verify', () => {
  const { groupPk, signerKeys } = dealShares(2, [1, 2, 3]);
  const policy: QuorumPolicy = { threshold: 2, windowMs: 60_000, perHourCap: 5 };
  const ch = mintChallenge('u', randomBytes(32));

  const active = signerKeys.slice(0, 2);
  const r1 = active.map((k) => commit(k));
  const commitments = r1.map((x) => x.publicCommitment);
  const partials = active.map((k, i) =>
    approve(k, r1[i]!.privateNonce, ch, commitments, groupPk),
  );
  const sig = aggregateApprovals(commitments, partials, ch, groupPk, policy);

  const wrong = { ...ch, boundTo: randomBytes(32) };
  assert.equal(verifyApproval(sig, wrong, groupPk, policy), false);
});

test('quorum (FROST): below-threshold is rejected at sign time', () => {
  const { groupPk, signerKeys } = dealShares(3, [1, 2, 3]);
  const ch = mintChallenge('u', randomBytes(32));
  const active = signerKeys.slice(0, 2); // one short
  const r1 = active.map((k) => commit(k));
  const commitments = r1.map((x) => x.publicCommitment);
  // A signer refuses to release a partial unless enough peers have committed —
  // protects signers from participating in a silently-below-threshold session.
  assert.throws(
    () => active.map((k, i) => approve(k, r1[i]!.privateNonce, ch, commitments, groupPk)),
    /below threshold/,
  );
});

test('quorum (FROST): expired challenge fails verification', async () => {
  const { groupPk, signerKeys } = dealShares(2, [1, 2]);
  const policy: QuorumPolicy = { threshold: 2, windowMs: 1, perHourCap: 5 };
  const ch = mintChallenge('x', randomBytes(32));
  const active = signerKeys.slice(0, 2);
  const r1 = active.map((k) => commit(k));
  const commitments = r1.map((x) => x.publicCommitment);
  const partials = active.map((k, i) =>
    approve(k, r1[i]!.privateNonce, ch, commitments, groupPk),
  );
  const sig = aggregateApprovals(commitments, partials, ch, groupPk, policy, ch.issuedAt);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(verifyApproval(sig, ch, groupPk, policy), false);
});

test('lightspeed: impossibly-fast RTT triggers self-destruct', () => {
  const seoul = { id: 'seo', lat: 37.55, lon: 126.99 };
  const ny = { id: 'nyc', lat: 40.71, lon: -74.01 };
  const floor = minLatencyMs(seoul, ny);
  assert.ok(floor > 40, `expected floor > 40ms, got ${floor}`);

  const node = createNode('seo', seoul);
  node.shards.set('a', new Uint8Array([1, 2, 3]));
  node.shards.set('b', new Uint8Array([4, 5, 6]));

  const order = guardNode(node, { from: ny, to: seoul, observedMs: 1 });
  assert.ok(order, 'expected migration order');
  assert.equal(order!.reason, 'impossibly-fast');
  assert.equal(node.alive, false);
  assert.equal(node.shards.size, 0);
});

test('lightspeed: normal latency is not flagged', () => {
  const a = { id: 'a', lat: 0, lon: 0 };
  const b = { id: 'b', lat: 0, lon: 10 };
  const floor = minLatencyMs(a, b);
  const anomaly = detect({ from: a, to: b, observedMs: floor * 2 });
  assert.equal(anomaly.kind, 'none');
});
