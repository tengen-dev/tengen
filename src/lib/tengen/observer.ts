/**
 * Observer detection — advisory alarm layer.
 *
 *   WHAT THIS IS: a set of best-effort heuristics that, if triggered,
 *   suggest the runtime is being observed (Node inspector, browser
 *   devtools, attached debugger). On a positive signal, the runtime wipes
 *   its own secrets and exits. No offensive response — the observer sees
 *   a clean shutdown and an empty process.
 *
 *   WHAT THIS IS NOT: a confidentiality boundary. A determined reverse
 *   engineer controls the runtime. They can shim `inspector.url()`, stub
 *   `performance.now()`, or patch out `debugger;` — we demonstrated this
 *   in audit.ts attack D. Treat these probes as a tripwire for
 *   opportunistic observation, not as defense against deliberate analysis.
 *
 * Security Boundary:
 *   ✓ Flags common, lazy observation (opening devtools on a shipped page,
 *     running `node --inspect` against a deployed binary).
 *   ✗ Does NOT stop a determined RE with runtime-patching capability.
 *   ✗ Produces false positives on slow machines (timing probe), on pages
 *     with legitimate console-logging middleware (getter probe), and in
 *     sandboxed embeds where inspector APIs are shimmed.
 *   ⚠ Intended as ONE layer of defense-in-depth. Do not build a trust
 *     decision on this probe alone. Pair with FROST-signed approvals,
 *     per-hop AES-GCM, and key expiration to keep the blast radius of a
 *     bypass bounded.
 */

/** Node.js: v8 inspector is attached → inspector.url() is non-null. */
export const isNodeInspected = async (): Promise<boolean> => {
  const proc = (globalThis as { process?: { versions?: { node?: string } } }).process;
  if (!proc?.versions?.node) return false;
  try {
    // Dynamic import keeps this browser-safe.
    const inspector = (await import('node:inspector')) as { url?: () => string | undefined };
    return typeof inspector.url === 'function' && inspector.url() != null;
  } catch {
    return false;
  }
};

/**
 * Browser: Chrome DevTools evaluates getters on objects passed to console
 * methods even when the console tab is not focused. A property-access trap
 * fires iff devtools is open.
 */
export const isBrowserDevtoolsOpen = (): boolean => {
  const doc = (globalThis as { document?: unknown }).document;
  if (typeof doc === 'undefined') return false;
  try {
    let triggered = false;
    const probe: Record<string, unknown> = {};
    Object.defineProperty(probe, 'id', {
      get() {
        triggered = true;
        return '';
      },
    });
    // eslint-disable-next-line no-console
    (globalThis as { console?: { debug?: (...a: unknown[]) => void } }).console?.debug?.(probe);
    return triggered;
  } catch {
    return false;
  }
};

/**
 * Timing check. A `debugger` statement with no breakpoint is a no-op, but
 * with a debugger attached it pauses execution. If a zero-work span measures
 * unusually long, something is stepping through us.
 */
export const isTimingAnomalous = (thresholdMs = 50): boolean => {
  const t0 = performance.now();
  // eslint-disable-next-line no-debugger
  debugger;
  const elapsed = performance.now() - t0;
  return elapsed > thresholdMs;
};

/** Heuristic aggregator — true if any passive probe indicates observation. */
export const isLikelyObserved = async (): Promise<boolean> => {
  if (await isNodeInspected()) return true;
  if (isBrowserDevtoolsOpen()) return true;
  if (isTimingAnomalous()) return true;
  return false;
};
