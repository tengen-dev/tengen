import { randomBytes, zeroize } from './primitives';

/**
 * Lightspeed — physical-distance tripwire.
 *
 * Real nodes are geographically dispersed. Each node holds an expected
 * minimum round-trip time (RTT) baseline to every other node, derived
 * from great-circle distance and speed of light in fiber (≈200,000 km/s,
 * i.e. c * 2/3). A packet that arrives *faster* than the great-circle
 * minimum suggests a man-in-the-middle with a shorter path; the node
 * self-destructs (zeroizes RAM state, emits migration order, rotates
 * keys). A packet that arrives too slowly or with anomalous jitter
 * triggers lighter key rotation without migration.
 *
 * Security Boundary:
 *   ✓ Catches MITM setups that short-cut the physical path (tunnelled
 *     through a closer relay, satellite vs terrestrial mismatch).
 *   ✗ Does NOT catch MITM that preserves or adds latency — an attacker
 *     sitting on the existing fiber path is undetectable by this probe.
 *     Pair with TLS + pinned certificates for path integrity.
 *   ✗ False positives under legitimate rerouting (BGP reconvergence,
 *     anycast flips, CDN edge migration). Treat individual trips as
 *     evidence, not proof; require sustained anomaly before migration.
 *   ⚠ Coordinates are metadata. If a node's coord leaks, the expected
 *     RTT profile to its peers leaks with it. Keep coords inside the
 *     coordinator's private state.
 */

export interface NodeCoord {
  readonly id: string;
  /** Latitude in degrees. */
  readonly lat: number;
  /** Longitude in degrees. */
  readonly lon: number;
}

const EARTH_KM = 6371;
const FIBER_KM_PER_MS = 200; // ~2/3 c in fiber

const greatCircleKm = (a: NodeCoord, b: NodeCoord): number => {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const φ1 = toRad(a.lat);
  const φ2 = toRad(b.lat);
  const Δφ = toRad(b.lat - a.lat);
  const Δλ = toRad(b.lon - a.lon);
  const x =
    Math.sin(Δφ / 2) ** 2 +
    Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) ** 2;
  return 2 * EARTH_KM * Math.asin(Math.sqrt(x));
};

/** Theoretical minimum one-way latency in ms (fiber, straight line). */
export const minLatencyMs = (a: NodeCoord, b: NodeCoord): number =>
  greatCircleKm(a, b) / FIBER_KM_PER_MS;

export interface LatencyProbe {
  readonly from: NodeCoord;
  readonly to: NodeCoord;
  readonly observedMs: number;
}

export type Anomaly =
  | { kind: 'none' }
  | { kind: 'impossibly-fast'; floorMs: number; observedMs: number }
  | { kind: 'unusually-slow'; floorMs: number; observedMs: number }
  | { kind: 'jitter-spike'; stddev: number };

/**
 * Detect an anomaly in a single probe, or across a sliding window of probes.
 * Returns the most severe finding.
 */
export const detect = (probe: LatencyProbe, history: readonly number[] = []): Anomaly => {
  const floor = minLatencyMs(probe.from, probe.to);
  // 5% safety margin on the physical floor — anything below is impossible.
  if (probe.observedMs < floor * 0.95) {
    return { kind: 'impossibly-fast', floorMs: floor, observedMs: probe.observedMs };
  }
  // Unusually slow: >8x the physical floor AND >200 ms absolute.
  if (probe.observedMs > Math.max(200, floor * 8)) {
    return { kind: 'unusually-slow', floorMs: floor, observedMs: probe.observedMs };
  }
  // Jitter spike: sliding-window stddev > 5x recent mean.
  if (history.length >= 8) {
    const mean = history.reduce((s, x) => s + x, 0) / history.length;
    const variance =
      history.reduce((s, x) => s + (x - mean) ** 2, 0) / history.length;
    const stddev = Math.sqrt(variance);
    if (stddev > mean * 5) return { kind: 'jitter-spike', stddev };
  }
  return { kind: 'none' };
};

/**
 * A live shard server's state. Holds its ephemeral keys and current
 * shard assignments in RAM only. Self-destruct wipes both and emits a
 * migration order for upstream coordinators.
 */
export interface ShardNode {
  readonly id: string;
  readonly coord: NodeCoord;
  keys: Uint8Array[];          // per-shard subkeys (RAM only)
  shards: Map<string, Uint8Array>; // addr -> body
  history: number[];           // sliding latency window
  alive: boolean;
}

export const createNode = (id: string, coord: NodeCoord): ShardNode => ({
  id,
  coord,
  keys: [],
  shards: new Map(),
  history: [],
  alive: true,
});

export interface MigrationOrder {
  readonly from: string;
  readonly reason: Anomaly['kind'];
  /** Addresses to re-scatter to new coordinates. Keys are *not* included —
   *  the caller will re-wrap under new subkeys at a new location. */
  readonly addrs: readonly string[];
}

/**
 * Self-destruct: wipe in-RAM keys + shard bodies, mark node dead, and
 * emit a migration order for the caller to act on. The node itself
 * cannot decide *where* to migrate to — that is the coordinator's role —
 * but it does decide *when*.
 */
export const selfDestruct = (node: ShardNode, reason: Anomaly['kind']): MigrationOrder => {
  const addrs = [...node.shards.keys()];
  for (const body of node.shards.values()) zeroize(body);
  node.shards.clear();
  for (const k of node.keys) zeroize(k);
  node.keys = [];
  node.alive = false;
  return { from: node.id, reason, addrs };
};

/**
 * Top-level guard: observe a probe, append to history, detect, and
 * trigger self-destruct on severity >= 'impossibly-fast'.
 */
export const guardNode = (node: ShardNode, probe: LatencyProbe): MigrationOrder | null => {
  if (!node.alive) return null;
  node.history.push(probe.observedMs);
  if (node.history.length > 64) node.history.shift();
  const a = detect(probe, node.history);
  if (a.kind === 'impossibly-fast') return selfDestruct(node, a.kind);
  if (a.kind === 'unusually-slow' || a.kind === 'jitter-spike') {
    // Lighter touch: rotate keys but don't migrate (yet).
    for (const k of node.keys) zeroize(k);
    node.keys = node.keys.map(() => randomBytes(32));
    return null;
  }
  return null;
};
