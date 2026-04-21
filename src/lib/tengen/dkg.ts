import { ed25519 } from '@noble/curves/ed25519';
import { _internal, type GroupPublicKey, type SignerKey } from './frost';

/**
 * Pedersen Distributed Key Generation (DKG) over Ed25519.
 *
 *   Eliminates the trusted-dealer window in frost.dealGroupKey().
 *   Every participant runs a Feldman VSS in parallel; no single host ever
 *   holds the full group secret. Each participant's final share is the
 *   sum of n local shares, one from every peer.
 *
 * Protocol (1 round, synchronous, assumes authenticated pair-wise channels):
 *
 *   1. Each P_i picks polynomial f_i(x) = a_{i,0} + a_{i,1}·x + …
 *      of degree t-1 with random coefficients in Z_n.
 *      P_i broadcasts Feldman commitments C_{i,k} = a_{i,k}·G  for k=0..t-1.
 *      P_i computes s_{i,j} = f_i(j) mod n  for each peer j, and sends
 *      s_{i,j} to P_j over a private authenticated channel.
 *
 *   2. Each P_j verifies every received share against its sender's
 *      commitments:
 *          s_{i,j}·G  ?==  sum_{k} (j^k) · C_{i,k}
 *      Any mismatch → abort (complaint / blame phase is NOT implemented
 *      here; see Security Boundary).
 *
 *   3. Each P_j aggregates:
 *          x_j = sum_i s_{i,j}   (P_j's final share of group sk)
 *          PK  = sum_i C_{i,0}   (group public key)
 *
 * Security Boundary:
 *   ✓ The group secret is never assembled anywhere. sk = sum_i a_{i,0}
 *     lives only in dispersed coefficients that each participant zeroizes
 *     locally after sending shares.
 *   ✓ A malicious dealer cannot forge shares: Feldman commitments force
 *     consistency between the share and the polynomial.
 *   ✗ This implementation does NOT run a complaint round. A participant
 *     who sends invalid shares causes abort, not exclusion. For adversarial
 *     settings, add RFC-9591-style blame + retry.
 *   ✗ Transport between participants is OUT OF SCOPE. Bad channels mean
 *     bad shares. Use mTLS, Noise, or equivalent between every pair.
 *   ⚠ Single-machine `dkgSimulate()` is for tests only — it runs every
 *     participant in one process, defeating the "no one holds sk" property.
 *     Do NOT use in production. Run `dkgStart/shareFor/…` on distinct hosts.
 */

const { modN, randScalar, G, IDENTITY, n } = _internal;

// ---- per-participant state ----------------------------------------------

export interface DkgParticipant {
  readonly id: number;
  readonly threshold: number;
  /** Our polynomial coefficients (a_{i,0}..a_{i,t-1}). Zeroized after shareFor loops. */
  coeffs: bigint[];
  /** Our Feldman commitments (broadcast these). */
  readonly commitments: Uint8Array[];
  /** Shares received from peers, keyed by sender id. */
  readonly receivedShares: Map<number, bigint>;
  /** Commitments received from peers, keyed by sender id. */
  readonly peerCommitments: Map<number, Uint8Array[]>;
}

export const dkgStart = (id: number, threshold: number): DkgParticipant => {
  if (threshold < 2) throw new Error('dkg: threshold must be >= 2');
  if (id < 1 || id > 255 || !Number.isInteger(id)) throw new Error('dkg: id in [1,255]');
  const coeffs: bigint[] = [];
  const commitments: Uint8Array[] = [];
  for (let k = 0; k < threshold; k++) {
    const a = randScalar();
    coeffs.push(a);
    commitments.push(G.multiply(a).toRawBytes());
  }
  return {
    id,
    threshold,
    coeffs,
    commitments,
    receivedShares: new Map(),
    peerCommitments: new Map(),
  };
};

/** Compute f_i(j) mod n — the share this participant sends to peer j. */
export const dkgShareFor = (me: DkgParticipant, peerId: number): bigint => {
  if (peerId < 1 || peerId > 255) throw new Error('dkg: peer id in [1,255]');
  const x = BigInt(peerId);
  let y = 0n;
  // Horner, high-degree first.
  for (let i = me.coeffs.length - 1; i >= 0; i--) y = modN(y * x + me.coeffs[i]!);
  return y;
};

/**
 * Verify a share received from peer `fromId` against their broadcast
 * commitments. Returns true iff the share lies on the claimed polynomial.
 */
export const dkgVerifyShare = (
  myId: number,
  share: bigint,
  peerCommitments: readonly Uint8Array[],
): boolean => {
  try {
    const j = BigInt(myId);
    const lhs = G.multiply(modN(share));
    let rhs = IDENTITY;
    let jPow = 1n;
    for (const cBytes of peerCommitments) {
      const C = ed25519.ExtendedPoint.fromHex(cBytes);
      rhs = rhs.add(C.multiply(jPow === 0n ? n - 1n : jPow));
      // Note: multiply(0n) is unsupported; the k=0 term has jPow=1, never 0.
      jPow = modN(jPow * j);
    }
    return lhs.equals(rhs);
  } catch {
    return false;
  }
};

/** Record a verified share from peer. Returns false + no-op if verify fails. */
export const dkgAcceptShare = (
  me: DkgParticipant,
  fromId: number,
  share: bigint,
  peerCommitments: readonly Uint8Array[],
): boolean => {
  if (!dkgVerifyShare(me.id, share, peerCommitments)) return false;
  me.receivedShares.set(fromId, modN(share));
  me.peerCommitments.set(fromId, [...peerCommitments]);
  return true;
};

/**
 * Finalize: aggregate all received shares into this participant's final
 * FROST share, and derive the group public key from the sum of all
 * participants' degree-0 commitments.
 *
 * `expectedParticipants` MUST be the full signer set agreed upon before
 * DKG started — including this participant. Missing any peer aborts.
 */
export const dkgFinalize = (
  me: DkgParticipant,
  expectedParticipants: readonly number[],
): { signerKey: SignerKey; groupPk: GroupPublicKey } => {
  if (new Set(expectedParticipants).size !== expectedParticipants.length) {
    throw new Error('dkg: duplicate participant id');
  }
  if (!expectedParticipants.includes(me.id)) {
    throw new Error('dkg: self not in expected participant set');
  }

  // Include our OWN share to ourselves.
  const myShareToSelf = dkgShareFor(me, me.id);
  let xSum = myShareToSelf;
  // Aggregate shares from every peer.
  for (const pid of expectedParticipants) {
    if (pid === me.id) continue;
    const s = me.receivedShares.get(pid);
    if (s === undefined) throw new Error(`dkg: missing share from peer ${pid}`);
    xSum = modN(xSum + s);
  }

  // Group PK = sum of every participant's a_{i,0}·G. Our own contribution
  // is commitments[0]; each peer's contribution is peerCommitments[pid][0].
  let pkPoint = ed25519.ExtendedPoint.fromHex(me.commitments[0]!);
  for (const pid of expectedParticipants) {
    if (pid === me.id) continue;
    const pc = me.peerCommitments.get(pid);
    if (!pc) throw new Error(`dkg: missing commitments from peer ${pid}`);
    pkPoint = pkPoint.add(ed25519.ExtendedPoint.fromHex(pc[0]!));
  }

  // Zeroize local coefficients — we still need our own share to ourselves,
  // but the polynomial itself (which could regenerate ANY peer share) is
  // no longer needed.
  for (let i = 0; i < me.coeffs.length; i++) me.coeffs[i] = 0n;

  return {
    signerKey: { id: me.id, sk: xSum },
    groupPk: { bytes: pkPoint.toRawBytes(), threshold: me.threshold },
  };
};

// ---- single-machine simulation (TESTS ONLY) -----------------------------

/**
 * Run the DKG across N in-process participants. Returns (groupPk, signerKeys)
 * in the same shape as frost.dealGroupKey. **For tests only** — a single
 * process holding every participant's state defeats the point of DKG.
 */
export const dkgSimulate = (
  threshold: number,
  signerIds: readonly number[],
): { groupPk: GroupPublicKey; signerKeys: SignerKey[] } => {
  if (signerIds.length < threshold) throw new Error('dkg: not enough signers');
  const locals = signerIds.map((id) => dkgStart(id, threshold));

  // Phase 1: broadcast commitments + exchange private shares with verification.
  for (const sender of locals) {
    for (const receiver of locals) {
      if (receiver.id === sender.id) continue;
      const share = dkgShareFor(sender, receiver.id);
      const ok = dkgAcceptShare(receiver, sender.id, share, sender.commitments);
      if (!ok) throw new Error(`dkg: share from ${sender.id} to ${receiver.id} failed verification`);
    }
  }

  // Phase 2: every participant finalizes. Sanity: all must agree on groupPk.
  const finals = locals.map((l) => dkgFinalize(l, signerIds));
  const pkHex = Buffer.from(finals[0]!.groupPk.bytes).toString('hex');
  for (const f of finals) {
    if (Buffer.from(f.groupPk.bytes).toString('hex') !== pkHex) {
      throw new Error('dkg: participants disagree on groupPk (bug or corrupted state)');
    }
  }
  return {
    groupPk: finals[0]!.groupPk,
    signerKeys: finals.map((f) => f.signerKey),
  };
};
