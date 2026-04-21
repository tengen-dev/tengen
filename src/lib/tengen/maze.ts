import { concat, hmacSha256, randomBytes } from './primitives';
import { verifyRoute, type EphemeralSession } from './ephemeral';
import { jitteredDelay, silent } from './ward';

/**
 * Labyrinth — the outer decoy layer.
 *
 *  • Every hit on an unknown path returns a plausible response.
 *  • A fresh fake subtree is minted on demand, so scanners burn time.
 *  • Fake responses match real ones in size, content-type, and timing.
 *  • A "scan pressure" signal multiplies decoy depth under probing.
 *
 * Security Boundary:
 *   ✓ Burns scanner time and obscures which paths are real.
 *   ✗ Does NOT protect the real paths from a targeted attacker who
 *     already knows the valid route format.
 *   ⚠ `scanPressure` is stored in-memory per-process. A distributed
 *     scan from many IPs each hits a cold maze unless you share pressure
 *     state across instances (which re-introduces the central-state
 *     anti-pattern the rest of Tengen avoids).
 */

const enc = new TextEncoder();

export interface MazeConfig {
  /** Key used to deterministically derive decoy content. Rotates per deploy. */
  readonly decoyKey: Uint8Array;
  /** Base number of children per decoy directory (grows under pressure). */
  readonly fanOut: number;
  /** Per-request scan pressure signal. 0 = normal, higher = more decoys. */
  scanPressure: number;
}

export const createMaze = (): MazeConfig => ({
  decoyKey: randomBytes(32),
  fanOut: 8,
  scanPressure: 0,
});

/** Probabilistically mark a request as scanner-like and bump pressure. */
export const observe = (m: MazeConfig, signals: { rapidRequests: boolean; unknownPaths: boolean }): void => {
  if (signals.rapidRequests) m.scanPressure = Math.min(8, m.scanPressure + 1);
  if (signals.unknownPaths) m.scanPressure = Math.min(8, m.scanPressure + 1);
  // Slow bleed-off so pressure naturally decays.
  if (!signals.rapidRequests && !signals.unknownPaths) m.scanPressure = Math.max(0, m.scanPressure - 1);
};

/** Derive deterministic decoy content for a path — same path → same bytes. */
export const decoyContent = async (
  m: MazeConfig,
  path: string,
  kind: 'listing' | 'blob',
): Promise<Uint8Array> => {
  const tag = await hmacSha256(m.decoyKey, concat(enc.encode(kind), enc.encode(path)));
  if (kind === 'listing') {
    // Generate a plausible-looking listing of N children whose names are
    // HMAC-derived — enumerating them reveals nothing and, when followed,
    // each child is itself a valid decoy.
    const depth = m.fanOut + m.scanPressure * 4;
    const children: string[] = [];
    for (let i = 0; i < depth; i++) {
      const h = await hmacSha256(m.decoyKey, concat(tag, new Uint8Array([i])));
      children.push(toB64u(h).slice(0, 16));
    }
    return enc.encode(JSON.stringify({ entries: children }));
  }
  // blob: size-randomized but deterministic from tag.
  const size = 512 + (tag[0] ?? 0) * 4;
  const out = new Uint8Array(size);
  for (let i = 0, cur = tag; i < size; i += cur.length) {
    out.set(cur.subarray(0, Math.min(cur.length, size - i)), i);
    cur = await hmacSha256(m.decoyKey, cur);
  }
  return out;
};

/**
 * Router entry point. Given a session and a request path:
 *   - if the path is a valid ephemeral route for this session → `real()` runs.
 *   - otherwise → a convincing decoy response is served; the caller cannot
 *     tell whether the path "existed" or not.
 */
export const guard = async (
  m: MazeConfig,
  session: EphemeralSession | null,
  path: string,
  real: () => Promise<Response>,
): Promise<Response> => {
  const token = extractToken(path);

  if (session && token && (await verifyRoute(session, token))) {
    // Real path — still pad timing to the decoy envelope so probes can't
    // distinguish it by latency.
    const [resp] = await Promise.all([real(), jitteredDelay()]);
    return resp;
  }

  observe(m, { rapidRequests: false, unknownPaths: true });
  await jitteredDelay();

  if (path.endsWith('/')) {
    const body = await decoyContent(m, path, 'listing');
    return new Response(body, {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  }
  const body = await decoyContent(m, path, 'blob');
  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' },
  });
};

/** Fallback silent response when even the maze doesn't want to answer. */
export const seal = async (): Promise<Response> => {
  await jitteredDelay();
  return silent();
};

const extractToken = (path: string): string | null => {
  // Convention: real paths are /_w/<token>, but this can be remapped freely.
  const m = /^\/_w\/([A-Za-z0-9_-]{40,})(?:\/|$)/.exec(path);
  return m ? m[1]! : null;
};

const toB64u = (b: Uint8Array): string => {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
