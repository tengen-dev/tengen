import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  applyIgnore,
  complianceFor,
  formatReport,
  hasAtLeast,
  parseIgnoreFile,
  scanSource,
  type Finding,
} from './scanner';
import { securityHeaders } from './headers';

test('scanner: flags SQL injection via template literal', () => {
  const src = "const q = `SELECT * FROM users WHERE id = ${userId}`;";
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'SQLI-TEMPLATE'));
});

test('scanner: does NOT flag parameterized sql-looking literal', () => {
  const src = 'const q = "SELECT * FROM users WHERE id = $1";';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.filter((f) => f.id === 'SQLI-TEMPLATE').length, 0);
});

test('scanner: flags eval + new Function', () => {
  const src =
    'function a(x) { return eval(x); }\n' +
    'const f = new Function("return 1");';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.filter((f) => f.id === 'EVAL').length, 2);
});

test('scanner: flags dangerouslySetInnerHTML', () => {
  const src = 'return <div dangerouslySetInnerHTML={{ __html: bio }} />;';
  const findings = scanSource('x.tsx', src);
  assert.ok(findings.some((f) => f.id === 'DANGEROUSLY-SET-INNERHTML'));
});

test('scanner: flags innerHTML = <variable>', () => {
  const src = 'element.innerHTML = userInput;';
  const findings = scanSource('x.js', src);
  assert.ok(findings.some((f) => f.id === 'INNERHTML'));
});

test('scanner: flags hardcoded API key patterns', () => {
  // NOTE: these strings ARE dummy/syntactic-only test fixtures; no real keys.
  const src =
    'const stripe = "sk_live_" + "abcdef0123456789abcdef01";\n' + // split to avoid secret-scan alert on real scanners
    'const token = "sk_live_abcdef0123456789abcdef01abcdef01";\n' +
    'const openai = "sk-' + 'a'.repeat(48) + '";';
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'HARDCODED-SECRET'));
});

test('scanner: flags Math.random() for token/session/password contexts', () => {
  const src =
    'const token = Math.random().toString(36);\n' +
    'const sessionId = Math.random() * 1e9;';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.filter((f) => f.id === 'MATH-RANDOM-SECURITY').length, 2);
});

test('scanner: ignores Math.random() in non-security contexts', () => {
  const src = 'const jitter = Math.random() * 100; // animation';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.filter((f) => f.id === 'MATH-RANDOM-SECURITY').length, 0);
});

test('scanner: flags JSON.parse(req.body)', () => {
  const src = 'const data = JSON.parse(req.body);';
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'JSON-PARSE-REQUEST'));
});

test('scanner: flags open redirect from query param', () => {
  const src = 'res.redirect(req.query.next);';
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'OPEN-REDIRECT'));
});

test('scanner: flags CORS wildcard with credentials', () => {
  const src = `cors({ origin: "*", credentials: true })`;
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'CORS-WILDCARD-CREDENTIALS'));
});

test('scanner: flags server env leaked to client component', () => {
  const src = `'use client';\nconst key = process.env.DATABASE_URL;`;
  const findings = scanSource('x.tsx', src);
  assert.ok(findings.some((f) => f.id === 'EXPOSED-ENV-CLIENT'));
});

test('scanner: ignores NEXT_PUBLIC_ envs in client components', () => {
  const src = `'use client';\nconst key = process.env.NEXT_PUBLIC_API_URL;`;
  const findings = scanSource('x.tsx', src);
  assert.equal(findings.filter((f) => f.id === 'EXPOSED-ENV-CLIENT').length, 0);
});

test('scanner: comments are not flagged', () => {
  const src = '// eval(x)\n/* const q = `SELECT ${id}` */\n// innerHTML = x';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.length, 0);
});

test('scanner: formatReport produces readable output', () => {
  const src = 'const q = `SELECT * FROM t WHERE id = ${id}`;';
  const findings = scanSource('x.ts', src);
  const report = formatReport(findings);
  assert.ok(report.includes('CRITICAL'));
  assert.ok(report.includes('SQLI-TEMPLATE'));
  assert.ok(report.includes('x.ts:1'));
});

test('scanner: empty findings produces a "clean but beware" note', () => {
  const report = formatReport([]);
  assert.ok(/does not mean the code is secure/i.test(report));
});

test('headers: default set includes CSP, HSTS, framing, and sane misc', () => {
  const h = securityHeaders();
  assert.ok(h['Content-Security-Policy']?.includes("default-src 'none'"));
  assert.ok(h['Strict-Transport-Security']?.includes('max-age='));
  assert.equal(h['X-Frame-Options'], 'DENY');
  assert.equal(h['X-Content-Type-Options'], 'nosniff');
  assert.equal(h['Referrer-Policy'], 'no-referrer');
});

test('headers: csp=off omits CSP', () => {
  const h = securityHeaders({ csp: 'off' });
  assert.equal(h['Content-Security-Policy'], undefined);
});

test('headers: next-app preset allows inline styles', () => {
  const h = securityHeaders({ csp: 'next-app' });
  assert.ok(h['Content-Security-Policy']?.includes("style-src 'self' 'unsafe-inline'"));
});

test('headers: explicit frame-ancestors replaces default DENY', () => {
  const h = securityHeaders({ frameAncestors: ["'self'", 'https://example.com'] });
  assert.equal(h['X-Frame-Options'], undefined);
  assert.ok(h['Content-Security-Policy']?.includes("frame-ancestors 'self' https://example.com"));
});

// ---- formatter + flag tests --------------------------------------------

const fixtureSrc = `
const q = \`SELECT * FROM t WHERE id = \${id}\`;
const token = Math.random().toString(36);
`;

test('formatReport: json mode returns parseable JSON with summary + findings', () => {
  const findings = scanSource('x.ts', fixtureSrc);
  const json = formatReport(findings, 'json');
  const parsed = JSON.parse(json);
  assert.equal(parsed.tool, 'tengen');
  assert.ok(parsed.summary.total >= 2);
  assert.ok(Array.isArray(parsed.findings));
  assert.equal(parsed.findings[0].severity, 'critical');
});

test('formatReport: markdown mode produces headings + code blocks', () => {
  const findings = scanSource('x.ts', fixtureSrc);
  const md = formatReport(findings, 'markdown');
  assert.ok(md.includes('# Tengen scan report'));
  assert.ok(md.includes('**Fix:**'));
  assert.ok(md.includes('```'));
});

test('formatReport: html mode produces a complete document', () => {
  const findings = scanSource('x.ts', fixtureSrc);
  const html = formatReport(findings, 'html');
  assert.ok(html.startsWith('<!doctype html>'));
  assert.ok(html.includes('</html>'));
  assert.ok(html.includes('SQLI-TEMPLATE'));
});

test('formatReport: compliance flag annotates each finding', () => {
  const findings = scanSource('x.ts', fixtureSrc);
  const txt = formatReport(findings, 'text', { compliance: true });
  assert.ok(txt.includes('OWASP'));
  assert.ok(txt.includes('CWE-'));
});

test('formatReport: html with compliance includes mapping block', () => {
  const findings = scanSource('x.ts', fixtureSrc);
  const html = formatReport(findings, 'html', { compliance: true });
  assert.ok(html.includes('class="comp"'));
});

test('complianceFor: known id returns a mapping', () => {
  const m = complianceFor('SQLI-TEMPLATE');
  assert.equal(m?.owaspTop10, 'A03:2021');
  assert.equal(m?.cwe, 'CWE-89');
});

test('complianceFor: unknown id returns undefined', () => {
  assert.equal(complianceFor('NO-SUCH-DETECTOR'), undefined);
});

test('parseIgnoreFile: blanks and # comments are skipped', () => {
  const rules = parseIgnoreFile(`
# this is a comment
SQLI-TEMPLATE

HARDCODED-SECRET:src/fixtures/
  `);
  assert.equal(rules.length, 2);
  assert.equal(rules[0]!.id, 'SQLI-TEMPLATE');
  assert.equal(rules[1]!.id, 'HARDCODED-SECRET');
  assert.ok(rules[1]!.fileRegex?.test('src/fixtures/whatever.ts'));
  assert.ok(!rules[1]!.fileRegex?.test('src/real/code.ts'));
});

test('applyIgnore: id-only rule suppresses everywhere', () => {
  const findings: readonly Finding[] = [
    { id: 'EVAL', file: 'a.ts', line: 1, severity: 'critical', title: '', snippet: '', why: '', fix: '' },
    { id: 'EVAL', file: 'b.ts', line: 1, severity: 'critical', title: '', snippet: '', why: '', fix: '' },
    { id: 'INNERHTML', file: 'c.ts', line: 1, severity: 'high', title: '', snippet: '', why: '', fix: '' },
  ];
  const out = applyIgnore(findings, parseIgnoreFile('EVAL'));
  assert.equal(out.length, 1);
  assert.equal(out[0]!.id, 'INNERHTML');
});

test('applyIgnore: id + file regex only suppresses matching files', () => {
  const findings: readonly Finding[] = [
    { id: 'HARDCODED-SECRET', file: 'src/fixtures/a.ts', line: 1, severity: 'critical', title: '', snippet: '', why: '', fix: '' },
    { id: 'HARDCODED-SECRET', file: 'src/prod.ts',       line: 1, severity: 'critical', title: '', snippet: '', why: '', fix: '' },
  ];
  const out = applyIgnore(findings, parseIgnoreFile('HARDCODED-SECRET:src/fixtures/'));
  assert.equal(out.length, 1);
  assert.equal(out[0]!.file, 'src/prod.ts');
});

test('applyIgnore: * wildcard rule suppresses everything under a path', () => {
  const findings: readonly Finding[] = [
    { id: 'EVAL', file: 'vendor/lib.js', line: 1, severity: 'critical', title: '', snippet: '', why: '', fix: '' },
    { id: 'EVAL', file: 'src/a.js',      line: 1, severity: 'critical', title: '', snippet: '', why: '', fix: '' },
  ];
  const out = applyIgnore(findings, parseIgnoreFile('*:vendor/'));
  assert.equal(out.length, 1);
  assert.equal(out[0]!.file, 'src/a.js');
});

test('hasAtLeast: true when finding at or above threshold exists', () => {
  const findings: readonly Finding[] = [
    { id: 'X', file: 'a', line: 1, severity: 'medium', title: '', snippet: '', why: '', fix: '' },
    { id: 'Y', file: 'b', line: 1, severity: 'high',   title: '', snippet: '', why: '', fix: '' },
  ];
  assert.equal(hasAtLeast(findings, 'high'), true);
  assert.equal(hasAtLeast(findings, 'critical'), false);
  assert.equal(hasAtLeast(findings, 'low'), true);
});
