import { randomBytes } from './primitives';

// Shamir secret sharing over GF(256) with the AES polynomial x^8 + x^4 + x^3 + x + 1.
// Each byte of the secret is split independently: y = f(x), f(0) = secretByte.
// Threshold k: any k distinct (x, y_i) pairs reconstruct the secret; k-1 reveal nothing.

const LOG = new Uint8Array(256);
const EXP = new Uint8Array(512);
(() => {
  // Generator 0x03 — primitive element of GF(256) under the Rijndael
  // polynomial 0x11b (x^8 + x^4 + x^3 + x + 1). Multiplying v by 3 =
  // (v << 1) XOR v, with reduction when bit 8 overflows.
  let v = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = v;
    LOG[v] = i;
    let next = (v << 1) ^ v;
    if (next & 0x100) next ^= 0x11b;
    v = next & 0xff;
  }
  // Double-length table so (LOG[a]+LOG[b]) can index without an explicit mod.
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
})();

const gfMul = (a: number, b: number): number => {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a]! + LOG[b]!) % 255]!;
};

const gfDiv = (a: number, b: number): number => {
  if (b === 0) throw new Error('shamir: division by zero');
  if (a === 0) return 0;
  return EXP[(LOG[a]! + 255 - LOG[b]!) % 255]!;
};

const evalPoly = (coeffs: Uint8Array, x: number): number => {
  // Horner, highest-degree first.
  let acc = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) acc = gfMul(acc, x) ^ coeffs[i]!;
  return acc;
};

export interface Share {
  readonly x: number;        // 1..255
  readonly y: Uint8Array;    // same length as secret
}

export const split = (secret: Uint8Array, k: number, n: number): Share[] => {
  if (k < 2 || n < k || n > 255) throw new Error('shamir: invalid (k,n)');
  if (secret.length === 0) throw new Error('shamir: empty secret');

  const xs = new Set<number>();
  while (xs.size < n) {
    const b = randomBytes(1)[0]!;
    if (b !== 0) xs.add(b);
  }
  return splitAtXs(secret, k, [...xs]);
};

/**
 * Like split() but evaluates the polynomial at caller-provided x-coords.
 * Useful when the x value carries identity (e.g. a signer id).
 */
export const splitAtXs = (secret: Uint8Array, k: number, xs: readonly number[]): Share[] => {
  const n = xs.length;
  if (k < 2 || n < k || n > 255) throw new Error('shamir: invalid (k,n)');
  if (secret.length === 0) throw new Error('shamir: empty secret');
  if (new Set(xs).size !== n) throw new Error('shamir: duplicate x');
  for (const x of xs) if (x === 0 || x > 255 || x < 0) throw new Error('shamir: x in [1,255]');

  const shares: Share[] = xs.map((x) => ({ x, y: new Uint8Array(secret.length) }));
  const coeffs = new Uint8Array(k);
  for (let i = 0; i < secret.length; i++) {
    coeffs[0] = secret[i]!;
    const rnd = randomBytes(k - 1);
    for (let j = 1; j < k; j++) coeffs[j] = rnd[j - 1]!;
    for (let s = 0; s < n; s++) shares[s]!.y[i] = evalPoly(coeffs, xs[s]!);
    coeffs.fill(0);
    rnd.fill(0);
  }
  return shares;
};

export const combine = (shares: readonly Share[]): Uint8Array => {
  if (shares.length < 2) throw new Error('shamir: need >=2 shares');
  const len = shares[0]!.y.length;
  for (const s of shares) {
    if (s.y.length !== len) throw new Error('shamir: length mismatch');
    if (s.x === 0) throw new Error('shamir: x=0 is reserved');
  }
  const xs = shares.map((s) => s.x);
  if (new Set(xs).size !== xs.length) throw new Error('shamir: duplicate x');

  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    let secret = 0;
    for (let j = 0; j < shares.length; j++) {
      let num = 1;
      let den = 1;
      const xj = shares[j]!.x;
      for (let m = 0; m < shares.length; m++) {
        if (m === j) continue;
        const xm = shares[m]!.x;
        num = gfMul(num, xm);        // evaluating Lagrange basis at x=0
        den = gfMul(den, xj ^ xm);
      }
      const lj = gfDiv(num, den);
      secret ^= gfMul(shares[j]!.y[i]!, lj);
    }
    out[i] = secret;
  }
  return out;
};
