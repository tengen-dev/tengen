import {
  aggregate as frostAggregate,
  burnNonce,
  commit as frostCommit,
  dealGroupKey as frostDeal,
  sign as frostSign,
  verify as frostVerify,
  type GroupPublicKey,
  type PartialSignature,
  type Signature,
  type SignerCommitment,
  type SignerKey,
  type SignerPrivateNonce,
} from './frost';
import { sha512 } from '@noble/hashes/sha512';
import { concat, randomBytes } from './primitives';

/**
 * Quorum — m-of-n human/node consent via FROST-Ed25519 threshold signing.
 *
 *   Signers hold Shamir shares of a group Ed25519 private key, but they
 *   NEVER transmit those shares. Each signing session they publish a pair
 *   of single-use nonce commitments, then release a partial scalar z_i
 *   computed as a linear combination of their share, their nonces, and
 *   the message hash. A passive observer cannot invert these equations
 *   without the unknown fresh nonces.
 *
 * Security Boundary:
 *   ✓ An attacker collecting partial signatures across any number of
 *     rounds cannot recover any signer's sk_i — the flaw that Attack A
 *     exploited in the previous Shamir-combine design is closed.
 *   ✓ Approvals are scoped to a specific message (the update binding).
 *     They cannot be replayed against a different message.
 *   ✗ Compromise of t signers (the threshold) IS game over — the group
 *     private key can be reconstructed from t shares, as always.
 *   ✗ Trusted-dealer setup briefly holds the group sk. Replace with DKG
 *     (out of scope) if that window is unacceptable.
 *   ⚠ The coordinator who collects commitments and partials can aggregate
 *     a signature, but cannot recover any signer's sk. A hostile
 *     coordinator who deviates from the protocol (e.g., providing
 *     inconsistent commitment lists to different signers) can cause a
 *     signing session to fail, but cannot forge a signature.
 */

const enc = new TextEncoder();

export interface Challenge {
  readonly id: Uint8Array;
  readonly purpose: string;
  readonly issuedAt: number;
  /** 32-byte value the signed message is derived from (e.g., update root). */
  readonly boundTo: Uint8Array;
}

export interface QuorumPolicy {
  readonly threshold: number;
  readonly windowMs: number;
  readonly perHourCap: number;
}

/** The message signers actually attest to. Deterministic in the challenge. */
export const messageForChallenge = (c: Challenge): Uint8Array => {
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(c.issuedAt));
  return sha512(
    concat(enc.encode(`tengen:quorum:msg:v1:${c.purpose}`), c.id, ts, c.boundTo),
  ).slice(0, 32);
};

// ---- deal / setup --------------------------------------------------------

export const dealShares = (
  threshold: number,
  signerIds: readonly number[],
): { groupPk: GroupPublicKey; signerKeys: readonly SignerKey[] } =>
  frostDeal(threshold, signerIds);

// ---- challenge mint ------------------------------------------------------

export const mintChallenge = (purpose: string, boundTo: Uint8Array): Challenge => ({
  id: randomBytes(32),
  purpose,
  issuedAt: Date.now(),
  boundTo,
});

// ---- signer-side: commit + sign ------------------------------------------

export { frostCommit as commit, burnNonce };

/**
 * Signer-side approval: produce a partial signature. The signer's sk is
 * NEVER transmitted — only `z_i` crosses the wire.
 */
export const approve = (
  key: SignerKey,
  nonce: SignerPrivateNonce,
  challenge: Challenge,
  peerCommitments: readonly SignerCommitment[],
  groupPk: GroupPublicKey,
): PartialSignature => {
  const msg = messageForChallenge(challenge);
  return frostSign(key, nonce, msg, peerCommitments, groupPk);
};

// ---- aggregate + verify --------------------------------------------------

/**
 * Coordinator-side: combine partial signatures into a full Schnorr signature
 * authorizing the challenge. Does not reveal any share material.
 */
export const aggregateApprovals = (
  commitments: readonly SignerCommitment[],
  partials: readonly PartialSignature[],
  challenge: Challenge,
  groupPk: GroupPublicKey,
  policy: QuorumPolicy,
  now = Date.now(),
): Signature => {
  if (now - challenge.issuedAt > policy.windowMs) throw new Error('quorum: window closed');
  if (partials.length < policy.threshold) throw new Error('quorum: below threshold');
  const msg = messageForChallenge(challenge);
  return frostAggregate(commitments, partials, msg, groupPk);
};

/**
 * Installer-side: verify a signature authorizes a given challenge against
 * the group public key. No quorum state required — just the group pk.
 */
export const verifyApproval = (
  sig: Signature,
  challenge: Challenge,
  groupPk: GroupPublicKey,
  policy: QuorumPolicy,
  now = Date.now(),
): boolean => {
  if (now - challenge.issuedAt > policy.windowMs) return false;
  const msg = messageForChallenge(challenge);
  return frostVerify(sig, msg, groupPk);
};

// ---- re-exports of types callers need ------------------------------------

export type {
  GroupPublicKey,
  PartialSignature,
  Signature,
  SignerCommitment,
  SignerKey,
  SignerPrivateNonce,
};
