import { b64u, concat, ctEqual, sha256 } from './primitives';
import type { DeploymentPackage } from './deploy';

/**
 * Integrity — tamper-evident canary over the full blob set + oblivious fetch.
 *
 *   Two cooperating mechanisms:
 *
 *     1. Merkle canary — at build time we compute a Merkle root over every
 *        blob (real + decoy) plus the entry IV, and embed it in the entry
 *        envelope. At runtime we verify before the first hop. A mismatch
 *        means SOMEONE touched the set between build and run — including
 *        decoys that the runtime would otherwise never notice. This is a
 *        reconnaissance alarm over the decoy surface.
 *
 *     2. Oblivious fetch — when reading blobs from a remote store, callers
 *        should fetch the FULL address set in sorted order at a uniform
 *        interval, then hand the fully-populated local Map to the runtime.
 *        The external observer sees one burst of N identically-sized
 *        requests at fixed spacing; nothing distinguishes real from decoy.
 *
 * Security Boundary:
 *   ✓ Merkle catches byte-level mutation of any blob before execution.
 *   ✓ Merkle catches addition or removal of blobs (map size change shifts
 *     the tree structure).
 *   ✓ obliviousFetchAll() makes request-order and request-timing carry
 *     zero information about which blobs are real (modulo response-size
 *     parity, which shatter/fragment ensures by padding decoys to match).
 *   ✗ Merkle runs ONCE before the loop. A blob mutated after verify but
 *     before its use is caught by per-hop AES-GCM, not by Merkle. Design
 *     accordingly: Merkle is the decoy canary, GCM is the hop guard.
 *   ⚠ Uniform interval leaks the fact that *something* is being fetched.
 *     It does not hide activity from a network observer — only the shape
 *     of the activity.
 */

const enc = new TextEncoder();

/**
 * Domain-separated Merkle tree over arbitrary byte entries.
 * Leaves are prefixed with 'L', internal nodes with 'N' — blocks
 * second-preimage attacks across levels.
 */
export const merkleRoot = async (entries: readonly Uint8Array[]): Promise<Uint8Array> => {
  if (entries.length === 0) return new Uint8Array(32);
  let level: Uint8Array[] = await Promise.all(
    entries.map((e) => sha256(concat(enc.encode('L'), e))),
  );
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i]!;
      const b = level[i + 1] ?? a;
      next.push(await sha256(concat(enc.encode('N'), a, b)));
    }
    level = next;
  }
  return level[0]!;
};

/**
 * Canonical deployment root: Merkle over {addr, body} pairs sorted by addr,
 * plus the entry IV. The entry envelope body itself is NOT part of the root
 * (the root lives inside it) — the envelope's own AES-GCM tag already
 * authenticates it end-to-end.
 */
export const deploymentRoot = async (
  blobs: ReadonlyMap<string, Uint8Array>,
  entryIv: Uint8Array,
): Promise<Uint8Array> => {
  const sorted = [...blobs.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const leaves: Uint8Array[] = [];
  for (const [addr, body] of sorted) {
    leaves.push(
      await sha256(
        concat(enc.encode('B'), b64u.decode(addr), new Uint8Array([0x00]), body),
      ),
    );
  }
  leaves.push(await sha256(concat(enc.encode('I'), entryIv)));
  return merkleRoot(leaves);
};

/** Constant-time Merkle root equality check. */
export const rootsEqual = (a: Uint8Array, b: Uint8Array): boolean => ctEqual(a, b);

/**
 * Verify a package's blobs against a known root. True iff every blob is
 * byte-identical to the build-time set.
 */
export const verifyPackage = async (
  pkg: DeploymentPackage,
  expectedRoot: Uint8Array,
): Promise<boolean> => {
  const actual = await deploymentRoot(pkg.blobs, pkg.entry.iv);
  return rootsEqual(actual, expectedRoot);
};

/**
 * Oblivious fetch: pull every address in `addrs` from `fetcher` at uniform
 * spacing, regardless of whether the caller needs each one. Returns a local
 * Map ready to hand to the runtime.
 *
 * Attack B mitigation: an external observer of `fetcher` sees the same
 * request pattern on every run — full set, sorted order, fixed interval.
 * They cannot distinguish real from decoy by access pattern.
 *
 * Trade-off: bandwidth scales with N (real + decoys), not with chain length.
 * Tune `decoys` in deploy() options to balance stealth vs cost.
 *
 * @param addrs       Full set of blob addresses (sorted internally).
 * @param fetcher     Callback that returns the blob body for a given addr.
 * @param intervalMs  Min spacing between successive requests. Default 0
 *                    issues requests back-to-back (burst of identical size).
 *                    A non-zero value enforces rhythm at the cost of time.
 */
export const obliviousFetchAll = async (
  addrs: Iterable<string>,
  fetcher: (addr: string) => Promise<Uint8Array | null>,
  intervalMs = 0,
): Promise<Map<string, Uint8Array>> => {
  const sorted = [...addrs].sort();
  const out = new Map<string, Uint8Array>();
  for (let i = 0; i < sorted.length; i++) {
    const addr = sorted[i]!;
    const start = Date.now();
    const body = await fetcher(addr);
    if (body) out.set(addr, body);
    if (intervalMs > 0 && i < sorted.length - 1) {
      const elapsed = Date.now() - start;
      const wait = Math.max(0, intervalMs - elapsed);
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    }
  }
  return out;
};
