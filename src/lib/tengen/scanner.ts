/**
 * Scanner — static-analysis heuristics for AI/vibe-coded JS/TS projects.
 *
 *   Regex-based, no AST. Fast, opinionated, and noisy on purpose: we want
 *   false positives more than false negatives, because the user we serve
 *   here is someone who didn't write the code themselves and can't tell
 *   which findings matter. Every finding includes a one-sentence
 *   explanation and a suggested fix.
 *
 * Security Boundary:
 *   ✓ Catches the common vulnerability classes AI coders generate without
 *     realizing: SQL injection via template literals, XSS via
 *     dangerouslySetInnerHTML / innerHTML, eval(), hardcoded API keys,
 *     Math.random() used for security-sensitive values, unvalidated
 *     JSON.parse of request bodies, open redirects.
 *   ✗ This is NOT a sound static analyzer. A real AST-based tool with
 *     dataflow (semgrep, CodeQL) catches far more. Use the scanner as a
 *     first-pass filter; pair with a real analyzer before shipping.
 *   ✗ Regex cannot understand semantics. If the flagged pattern is
 *     actually safe in your case, review and move on. If the scanner
 *     doesn't find anything, it does NOT mean your code is secure.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  readonly id: string;
  readonly file: string;
  readonly line: number;
  readonly severity: Severity;
  readonly title: string;
  readonly snippet: string;
  readonly why: string;
  readonly fix: string;
}

/**
 * Compliance mapping: each scanner detector is cross-referenced to the
 * controls auditors care about. Keep these short — auditors don't need
 * explanations, they need the control ID so they can tick a box.
 */
export interface ComplianceMap {
  readonly owaspTop10?: string;
  readonly cwe?: string;
  readonly soc2?: string;
  readonly iso27001?: string;
}

const COMPLIANCE: Record<string, ComplianceMap> = {
  'SQLI-TEMPLATE':           { owaspTop10: 'A03:2021', cwe: 'CWE-89',  soc2: 'CC6.1', iso27001: 'A.8.28' },
  'EVAL':                    { owaspTop10: 'A03:2021', cwe: 'CWE-95',  soc2: 'CC6.1', iso27001: 'A.8.28' },
  'INNERHTML':               { owaspTop10: 'A03:2021', cwe: 'CWE-79',  soc2: 'CC6.1', iso27001: 'A.8.28' },
  'DANGEROUSLY-SET-INNERHTML': { owaspTop10: 'A03:2021', cwe: 'CWE-79', soc2: 'CC6.1', iso27001: 'A.8.28' },
  'HARDCODED-SECRET':        { owaspTop10: 'A07:2021', cwe: 'CWE-798', soc2: 'CC6.1', iso27001: 'A.8.24' },
  'JWT-HARDCODED-SECRET':    { owaspTop10: 'A02:2021', cwe: 'CWE-798', soc2: 'CC6.1', iso27001: 'A.8.24' },
  'MATH-RANDOM-SECURITY':    { owaspTop10: 'A02:2021', cwe: 'CWE-338', soc2: 'CC6.7', iso27001: 'A.8.24' },
  'JSON-PARSE-REQUEST':      { owaspTop10: 'A03:2021', cwe: 'CWE-20',  soc2: 'CC6.1', iso27001: 'A.8.28' },
  'OPEN-REDIRECT':           { owaspTop10: 'A01:2021', cwe: 'CWE-601', soc2: 'CC6.1', iso27001: 'A.8.28' },
  'CORS-WILDCARD-CREDENTIALS': { owaspTop10: 'A05:2021', cwe: 'CWE-942', soc2: 'CC6.1', iso27001: 'A.5.14' },
  'EXPOSED-ENV-CLIENT':      { owaspTop10: 'A05:2021', cwe: 'CWE-200', soc2: 'CC6.1', iso27001: 'A.8.2' },
};

export const complianceFor = (id: string): ComplianceMap | undefined => COMPLIANCE[id];

export interface ScanOptions {
  /** Only scan files with these extensions. */
  readonly extensions?: readonly string[];
  /** Skip directory names (recursive). */
  readonly skipDirs?: readonly string[];
  /** Max file size in bytes; larger files are skipped. */
  readonly maxBytes?: number;
}

const DEFAULTS: Required<ScanOptions> = {
  extensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'],
  skipDirs: ['node_modules', 'dist', 'build', '.next', '.git', 'coverage', '.turbo', 'out'],
  maxBytes: 1_000_000,
};

// ---- detectors ----------------------------------------------------------

interface Detector {
  readonly id: string;
  readonly severity: Severity;
  readonly title: string;
  readonly why: string;
  readonly fix: string;
  readonly test: (line: string, fullSource: string) => boolean;
}

const DETECTORS: readonly Detector[] = [
  {
    id: 'SQLI-TEMPLATE',
    severity: 'critical',
    title: 'SQL query built with template literal + variable interpolation',
    why: 'Concatenating user-controlled values into a SQL string is the textbook SQL-injection bug. Any attacker who controls the variable controls your database.',
    fix: "Use your driver's parameterized API. With tengen's ward: `import { paramOnly } from 'tengen'; const q = paramOnly`SELECT * FROM t WHERE id=${id}`; driver.query(q.text, q.values);`",
    test: (line) =>
      /`[^`]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|VALUES|SET)\b[^`]*\$\{[^}]+\}[^`]*`/i.test(line),
  },
  {
    id: 'EVAL',
    severity: 'critical',
    title: 'eval() or new Function() on a string',
    why: 'eval and Function constructors execute arbitrary strings as code. If any piece of that string ever comes from user input, it is remote code execution.',
    fix: 'Replace with explicit branching / JSON.parse / switch. If you need dynamic code, look for a schema-driven interpreter, not eval.',
    test: (line) =>
      /(^|[^A-Za-z0-9_$])eval\s*\(/.test(line) || /\bnew\s+Function\s*\(/.test(line),
  },
  {
    id: 'INNERHTML',
    severity: 'high',
    title: '.innerHTML assigned a non-literal value',
    why: 'Assigning untrusted strings to innerHTML is the classic DOM XSS path. Any <script>, onerror, onclick embedded in the value runs in your origin.',
    fix: 'Use .textContent for plain text, or sanitize with DOMPurify before assigning innerHTML. For React, never bypass JSX escaping.',
    test: (line) => /\.innerHTML\s*=\s*(?!["'`][^"'`]*["'`]\s*;?\s*$)[^=]/.test(line),
  },
  {
    id: 'DANGEROUSLY-SET-INNERHTML',
    severity: 'high',
    title: 'React dangerouslySetInnerHTML',
    why: 'The name is a warning: any value passed here is injected as raw HTML. Without DOMPurify (or equivalent), an attacker-controlled string becomes XSS.',
    fix: 'Prefer plain children so JSX escapes for you. If you truly need HTML, sanitize with DOMPurify first.',
    test: (line) => /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html/.test(line),
  },
  {
    id: 'HARDCODED-SECRET',
    severity: 'critical',
    title: 'Hardcoded API key or token in source',
    why: 'Secrets in source are leaked the moment the repo goes anywhere — GitHub, a colleague, a CI log, an AI assistant. Once committed, they must be rotated.',
    fix: 'Move the value to an environment variable. Add .env to .gitignore. Rotate the secret because it is already effectively public.',
    test: (line) => {
      // Stripe / GitHub / Slack / AWS / OpenAI / generic
      if (/['"`]sk_(live|test)_[A-Za-z0-9]{16,}['"`]/.test(line)) return true;
      if (/['"`]ghp_[A-Za-z0-9]{30,}['"`]/.test(line)) return true;
      if (/['"`]xox[baprs]-[A-Za-z0-9-]{20,}['"`]/.test(line)) return true;
      if (/['"`]AKIA[A-Z0-9]{16}['"`]/.test(line)) return true;
      if (/['"`]sk-[A-Za-z0-9]{32,}['"`]/.test(line)) return true; // OpenAI
      if (/['"`]AIza[A-Za-z0-9_-]{35}['"`]/.test(line)) return true; // Google
      return false;
    },
  },
  {
    id: 'JWT-HARDCODED-SECRET',
    severity: 'critical',
    title: 'JWT signing secret hardcoded',
    why: 'If your JWT signing key is a short literal in code, anyone who reads the repo can forge tokens. Also defeats rotation.',
    fix: 'Load the secret from process.env at startup; rotate if this ever shipped. Consider an asymmetric key (RS256/EdDSA) so you can publish the verifier publicly.',
    test: (line) => {
      // Must reference jwt/jsonwebtoken somewhere on the line AND call .sign
      // with a literal string as the 2nd argument.
      if (!/\b(jwt|jsonwebtoken)\b/i.test(line)) return false;
      return /\.sign\s*\(\s*[^,()]+,\s*['"`][^'"`]{4,}['"`]/.test(line);
    },
  },
  {
    id: 'MATH-RANDOM-SECURITY',
    severity: 'high',
    title: 'Math.random() used for a security-sensitive value',
    why: 'Math.random is predictable to anyone who observes its output for a while. Tokens, session ids, password reset codes, OTPs, nonces all need cryptographic randomness.',
    fix: 'Use crypto.getRandomValues(new Uint8Array(n)) in browsers/Node; crypto.randomBytes(n) in Node only. Tengen ships randomBytes() as a convenience.',
    test: (line) => {
      if (!/Math\.random\s*\(\s*\)/.test(line)) return false;
      // Match "token", "sessionId", "csrfToken", "passwordHash", etc.
      // Not using \b because AI-written code prefers camelCase compounds.
      return /(token|secret|session|password|reset|otp|nonce|salt|csrf|apikey|api_key)/i.test(line);
    },
  },
  {
    id: 'JSON-PARSE-REQUEST',
    severity: 'medium',
    title: 'JSON.parse() directly on request input without schema',
    why: 'Parsing untrusted JSON without shape validation exposes your handler to deeply-nested objects (DoS), prototype pollution, and unexpected types that crash downstream code.',
    fix: "Validate with zod or similar BEFORE trusting the shape. Tengen's ward provides `gate(schema, raw)` that returns `{ ok, value }` without throwing.",
    test: (line) =>
      /JSON\.parse\s*\(\s*(?:req\.body|request\.body|ctx\.request\.body|event\.body|params\.\w+|searchParams\.\w+)/.test(line),
  },
  {
    id: 'OPEN-REDIRECT',
    severity: 'medium',
    title: 'Redirect target derived from user input',
    why: 'If the redirect URL comes from a query parameter or request body, an attacker can craft a phishing link that looks like it came from your domain but bounces to theirs.',
    fix: 'Allowlist redirect targets. Accept only a short code the client sends; map the code to a server-side URL constant.',
    test: (line) =>
      /(res|response)\s*\.\s*redirect\s*\(\s*(req\.|request\.|searchParams|params)/.test(line) ||
      /Response\s*\.\s*redirect\s*\(\s*(req\.|request\.|searchParams|params)/.test(line),
  },
  {
    id: 'CORS-WILDCARD-CREDENTIALS',
    severity: 'high',
    title: 'CORS * with credentials',
    why: 'Access-Control-Allow-Origin: * combined with credentials: true lets any site read authenticated responses from your API. Browsers usually block this combination, but if you set the header manually it is still a misconfiguration.',
    fix: 'List concrete origins or reflect the origin after checking it against an allowlist. Never mix wildcard with credentials.',
    test: (line) =>
      /['"]Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/.test(line) ||
      /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"][^}]*credentials\s*:\s*true/.test(line),
  },
  {
    id: 'EXPOSED-ENV-CLIENT',
    severity: 'medium',
    title: 'process.env leaked to client bundle',
    why: 'Anything in a React/Next client component that references a non-NEXT_PUBLIC_ env var ships in the JS bundle. Server-only secrets become public on first page load.',
    fix: "Rename client-exposed variables to NEXT_PUBLIC_* so the leak is explicit. Keep server-only secrets behind API routes.",
    test: (line, src) => {
      if (!/process\.env\.([A-Za-z_][A-Za-z0-9_]*)/.test(line)) return false;
      const isClient = /^\s*['"]use client['"]/m.test(src);
      if (!isClient) return false;
      const m = /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
      return !!(m && !m[1]!.startsWith('NEXT_PUBLIC_'));
    },
  },
];

// ---- scanner core -------------------------------------------------------

const isInComment = (line: string): boolean => /^\s*(\/\/|\*|\/\*)/.test(line);

export const scanSource = (file: string, src: string): Finding[] => {
  const findings: Finding[] = [];
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (isInComment(line)) continue;
    for (const d of DETECTORS) {
      if (d.test(line, src)) {
        findings.push({
          id: d.id,
          file,
          line: i + 1,
          severity: d.severity,
          title: d.title,
          snippet: line.trim().slice(0, 160),
          why: d.why,
          fix: d.fix,
        });
      }
    }
  }
  return findings;
};

const walk = async (
  dir: string,
  root: string,
  opts: Required<ScanOptions>,
  out: string[],
): Promise<void> => {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (opts.skipDirs.includes(entry.name)) continue;
      await walk(full, root, opts, out);
    } else if (entry.isFile()) {
      if (!opts.extensions.some((ext) => entry.name.endsWith(ext))) continue;
      const s = await stat(full);
      if (s.size > opts.maxBytes) continue;
      out.push(full);
    }
  }
};

export const scanDir = async (rootDir: string, opts: ScanOptions = {}): Promise<Finding[]> => {
  const merged: Required<ScanOptions> = {
    extensions: opts.extensions ?? DEFAULTS.extensions,
    skipDirs: opts.skipDirs ?? DEFAULTS.skipDirs,
    maxBytes: opts.maxBytes ?? DEFAULTS.maxBytes,
  };
  const root = resolve(rootDir);
  const files: string[] = [];
  await walk(root, root, merged, files);
  const findings: Finding[] = [];
  for (const f of files) {
    const src = await readFile(f, 'utf8');
    for (const finding of scanSource(relative(root, f), src)) findings.push(finding);
  }
  return findings;
};

// ---- ignore files -------------------------------------------------------

/**
 * Parse a `.tengenignore`-style file. Each non-empty, non-`#` line is a
 * pattern of the form `<id>:<file-regex>` or just `<id>`. Findings whose
 * (id, file) match any rule are dropped. Regex is anchored to the start
 * of the relative path.
 */
export interface IgnoreRule {
  readonly id: string; // detector id or '*'
  readonly fileRegex?: RegExp;
}

export const parseIgnoreFile = (content: string): IgnoreRule[] => {
  const rules: IgnoreRule[] = [];
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const sep = line.indexOf(':');
    if (sep === -1) {
      rules.push({ id: line });
    } else {
      const id = line.slice(0, sep).trim();
      const pattern = line.slice(sep + 1).trim();
      try {
        rules.push({ id, fileRegex: new RegExp('^' + pattern) });
      } catch {
        rules.push({ id });
      }
    }
  }
  return rules;
};

const matchesIgnore = (f: Finding, rules: readonly IgnoreRule[]): boolean =>
  rules.some((r) => {
    if (r.id !== '*' && r.id !== f.id) return false;
    if (!r.fileRegex) return true;
    return r.fileRegex.test(f.file);
  });

export const applyIgnore = (findings: readonly Finding[], rules: readonly IgnoreRule[]): Finding[] =>
  findings.filter((f) => !matchesIgnore(f, rules));

// ---- formatters ---------------------------------------------------------

export type Format = 'text' | 'json' | 'markdown' | 'html';

const SEV_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const sortFindings = (findings: readonly Finding[]): Finding[] =>
  [...findings].sort((a, b) => {
    if (SEV_ORDER[b.severity] !== SEV_ORDER[a.severity]) return SEV_ORDER[b.severity] - SEV_ORDER[a.severity];
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

const countBySev = (findings: readonly Finding[]): Record<Severity, number> => {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
};

export interface FormatOptions {
  /** Include OWASP / CWE / SOC 2 / ISO 27001 mapping in the output. */
  readonly compliance?: boolean;
}

const textReport = (findings: readonly Finding[], opts: FormatOptions = {}): string => {
  if (findings.length === 0) {
    return 'tengen scan: 0 findings. Note: a clean report does not mean the code is secure.\n';
  }
  const sorted = sortFindings(findings);
  const c = countBySev(sorted);
  const header =
    `tengen scan — ${findings.length} finding(s) ` +
    `(critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low})\n` +
    '─'.repeat(72) + '\n';
  const body = sorted
    .map((f, i) => {
      const compline = opts.compliance
        ? '\n    compliance: ' + renderComplianceLine(f.id)
        : '';
      return `\n[${i + 1}] ${f.severity.toUpperCase()} · ${f.id}  ${f.file}:${f.line}\n` +
        `    ${f.title}\n` +
        `    > ${f.snippet}\n` +
        `    why: ${f.why}\n` +
        `    fix: ${f.fix}` +
        compline;
    })
    .join('\n');
  return header + body + '\n';
};

const renderComplianceLine = (id: string): string => {
  const c = COMPLIANCE[id];
  if (!c) return '(unmapped)';
  const parts: string[] = [];
  if (c.owaspTop10) parts.push(`OWASP ${c.owaspTop10}`);
  if (c.cwe) parts.push(c.cwe);
  if (c.soc2) parts.push(`SOC2 ${c.soc2}`);
  if (c.iso27001) parts.push(`ISO27001 ${c.iso27001}`);
  return parts.join(' · ');
};

const jsonReport = (findings: readonly Finding[], opts: FormatOptions = {}): string => {
  const sorted = sortFindings(findings);
  const c = countBySev(sorted);
  const payload = {
    tool: 'tengen',
    version: '0.0.1-research',
    generatedAt: new Date().toISOString(),
    summary: {
      total: findings.length,
      critical: c.critical,
      high: c.high,
      medium: c.medium,
      low: c.low,
    },
    findings: sorted.map((f) => ({
      id: f.id,
      file: f.file,
      line: f.line,
      severity: f.severity,
      title: f.title,
      snippet: f.snippet,
      why: f.why,
      fix: f.fix,
      ...(opts.compliance ? { compliance: COMPLIANCE[f.id] ?? {} } : {}),
    })),
  };
  return JSON.stringify(payload, null, 2) + '\n';
};

const escapeHtml = (s: string): string =>
  s.replace(/[&<>"']/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : c === '"' ? '&quot;' : '&#39;',
  );

const markdownReport = (findings: readonly Finding[], opts: FormatOptions = {}): string => {
  const sorted = sortFindings(findings);
  const c = countBySev(sorted);
  if (sorted.length === 0) {
    return `# Tengen scan report\n\n**0 findings.** A clean report does not mean the code is secure.\n`;
  }
  const header =
    `# Tengen scan report\n\n` +
    `Generated ${new Date().toISOString()}\n\n` +
    `| Critical | High | Medium | Low | Total |\n` +
    `|---------:|-----:|-------:|----:|------:|\n` +
    `| ${c.critical} | ${c.high} | ${c.medium} | ${c.low} | ${sorted.length} |\n\n`;
  const body = sorted
    .map((f, i) => {
      const comp = opts.compliance
        ? `\n**Compliance:** ${renderComplianceLine(f.id)}\n`
        : '';
      return `## ${i + 1}. ${f.severity.toUpperCase()} — ${f.title}\n\n` +
        `**${f.id}** · \`${f.file}:${f.line}\`\n\n` +
        '```\n' + f.snippet + '\n```\n\n' +
        `**Why this matters:** ${f.why}\n\n` +
        `**Fix:** ${f.fix}\n` +
        comp;
    })
    .join('\n');
  return header + body;
};

const htmlReport = (findings: readonly Finding[], opts: FormatOptions = {}): string => {
  const sorted = sortFindings(findings);
  const c = countBySev(sorted);
  const sevColor: Record<Severity, string> = {
    critical: '#b91c1c', high: '#c2410c', medium: '#a16207', low: '#4d7c0f',
  };
  const rows = sorted.map((f, i) => {
    const comp = opts.compliance
      ? `<div class="comp">${escapeHtml(renderComplianceLine(f.id))}</div>`
      : '';
    return `
<section class="finding">
  <div class="head">
    <span class="badge" style="background:${sevColor[f.severity]}">${f.severity.toUpperCase()}</span>
    <span class="id">${escapeHtml(f.id)}</span>
    <span class="loc">${escapeHtml(f.file)}:${f.line}</span>
    <span class="num">#${i + 1}</span>
  </div>
  <h3>${escapeHtml(f.title)}</h3>
  <pre><code>${escapeHtml(f.snippet)}</code></pre>
  <p><strong>Why:</strong> ${escapeHtml(f.why)}</p>
  <p><strong>Fix:</strong> ${escapeHtml(f.fix)}</p>
  ${comp}
</section>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Tengen scan report</title>
<style>
  :root { font-family: ui-sans-serif, system-ui, sans-serif; line-height: 1.5; color:#111; }
  body { max-width: 920px; margin: 2rem auto; padding: 0 1rem; }
  h1 { margin: 0 0 .5rem; }
  .meta { color:#666; font-size:.9rem; margin-bottom: 1rem; }
  table { border-collapse: collapse; margin-bottom: 2rem; }
  td, th { padding: .35rem .75rem; border: 1px solid #ddd; text-align: right; font-variant-numeric: tabular-nums; }
  th { background:#f5f5f5; }
  .finding { border: 1px solid #e5e5e5; border-radius: 6px; padding: 1rem 1.25rem; margin: 1rem 0; background:#fafafa; }
  .head { display:flex; gap:.75rem; align-items:center; margin-bottom:.25rem; font-size:.85rem; color:#555; }
  .badge { color:#fff; padding: .1rem .5rem; border-radius: 3px; font-weight:600; font-size:.75rem; }
  .id { font-family: ui-monospace, monospace; color:#333; }
  .loc { font-family: ui-monospace, monospace; color:#777; }
  .num { margin-left:auto; color:#aaa; }
  h3 { margin: .25rem 0 .5rem; }
  pre { background:#f0f0f0; padding:.5rem .75rem; border-radius:4px; overflow-x:auto; }
  .comp { font-size:.85rem; color:#555; margin-top:.25rem; border-top:1px dashed #ddd; padding-top:.4rem; }
  footer { color:#666; font-size:.85rem; margin-top: 2rem; }
</style>
</head><body>
<h1>Tengen scan report</h1>
<div class="meta">generated ${new Date().toISOString()} · tengen 0.0.1-research</div>
<table>
  <thead><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead>
  <tbody><tr>
    <td>${c.critical}</td><td>${c.high}</td><td>${c.medium}</td><td>${c.low}</td><td>${sorted.length}</td>
  </tr></tbody>
</table>
${sorted.length === 0 ? '<p><em>0 findings. A clean report does not mean the code is secure.</em></p>' : rows}
<footer>
  Tengen is pre-audit research code. The scanner is a heuristic first-pass; pair with a sound
  static analyzer (Semgrep, CodeQL) before shipping. Missing detection does not imply safety.
</footer>
</body></html>
`;
};

export const formatReport = (
  findings: readonly Finding[],
  format: Format = 'text',
  opts: FormatOptions = {},
): string => {
  switch (format) {
    case 'json':     return jsonReport(findings, opts);
    case 'markdown': return markdownReport(findings, opts);
    case 'html':     return htmlReport(findings, opts);
    case 'text':
    default:         return textReport(findings, opts);
  }
};

// ---- gate helpers -------------------------------------------------------

/** Return true if findings include any at or above the given severity. */
export const hasAtLeast = (findings: readonly Finding[], min: Severity): boolean => {
  const minRank = SEV_ORDER[min];
  return findings.some((f) => SEV_ORDER[f.severity] >= minRank);
};
