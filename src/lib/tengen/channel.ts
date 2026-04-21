import { concat, hkdf, hmacSha256, randomBytes, sha256, zeroize } from './primitives';

/**
 * Mathematical-gate channel.
 *
 *   For each edge (i → i+1) of a fragmented network we build a puzzle:
 *
 *     given edgeSecret s  and  outputDigest d  (= H(node_i execution result)),
 *     find nonce r  such that  sha256( s || d || r )  starts with `difficulty` zero bits.
 *
 *   The solver must (a) possess edgeSecret s  AND  (b) have actually executed
 *   node i (producing d). The solution r deterministically derives the
 *   decryption key for node i+1:
 *
 *     edgeKey_{i+1} = HKDF( s || r,  salt = d,  info = "tengen:edge:v1" )
 *
 *   The channel this opens is time-boxed: ttlMs (default 1 ms). After the
 *   TTL, s and r are zeroized and the key evaporates even if the runtime
 *   has not yet progressed.
 */

const enc = new TextEncoder();

export interface EdgePuzzle {
  readonly difficulty: number; // leading zero *bits* required
  readonly ttlMs: number;
}

export interface Solution {
  readonly nonce: Uint8Array;
  readonly digest: Uint8Array; // H(s || d || r) — solution output
}

const leadingZeroBits = (b: Uint8Array, want: number): boolean => {
  const fullBytes = want >> 3;
  const rem = want & 7;
  for (let i = 0; i < fullBytes; i++) if (b[i] !== 0) return false;
  if (rem === 0) return true;
  const mask = 0xff << (8 - rem);
  return ((b[fullBytes] ?? 0) & mask) === 0;
};

export const solve = async (
  edgeSecret: Uint8Array,
  outputDigest: Uint8Array,
  puzzle: EdgePuzzle,
): Promise<Solution> => {
  const r = new Uint8Array(8);
  const prefix = concat(edgeSecret, outputDigest);
  // Bounded linear search — difficulty ≈ 16 keeps each hop well under ttlMs.
  for (let i = 0; i < 1 << 24; i++) {
    new DataView(r.buffer).setUint32(0, i);
    const d = await sha256(concat(prefix, r));
    if (leadingZeroBits(d, puzzle.difficulty)) {
      return { nonce: r.slice(), digest: d };
    }
  }
  throw new Error('channel: puzzle unsolved within budget');
};

export const verify = async (
  edgeSecret: Uint8Array,
  outputDigest: Uint8Array,
  solution: Solution,
  puzzle: EdgePuzzle,
): Promise<boolean> => {
  const d = await sha256(concat(edgeSecret, outputDigest, solution.nonce));
  if (!leadingZeroBits(d, puzzle.difficulty)) return false;
  return d.every((b, i) => b === (solution.digest[i] ?? 0));
};

/**
 * Derive the next node's decryption key from (edgeSecret, solution).
 * The caller must zeroize the returned key ASAP — or just wait for the
 * ttlMs channel to auto-wipe it (see openChannel below).
 */
export const deriveNextKey = (
  edgeSecret: Uint8Array,
  outputDigest: Uint8Array,
  solution: Solution,
): Promise<Uint8Array> =>
  hkdf(
    concat(edgeSecret, solution.nonce),
    outputDigest,
    enc.encode('tengen:edge:v1'),
    32,
  );

/**
 * A 1ms (or user-chosen) channel that holds the next-node decryption key.
 * Past the deadline, the key is zero-filled unconditionally. Consumers that
 * haven't finished get a dead key and the chain snaps.
 */
export interface Channel {
  /** Returns the live key, or null if the channel is already closed. */
  use(): Uint8Array | null;
  /** Explicit close; idempotent. */
  close(): void;
}

export const openChannel = (key: Uint8Array, ttlMs = 1): Channel => {
  let alive = true;
  const timer: ReturnType<typeof setTimeout> = setTimeout(() => {
    alive = false;
    zeroize(key);
  }, ttlMs);
  return {
    use: () => (alive ? key : null),
    close: () => {
      if (!alive) return;
      alive = false;
      clearTimeout(timer);
      zeroize(key);
    },
  };
};

export const mintEdgeSecret = (): Uint8Array => randomBytes(32);

export const digestExecution = async (output: Uint8Array): Promise<Uint8Array> =>
  hmacSha256(await sha256(enc.encode('tengen:exec:v1')), output);
