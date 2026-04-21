# Tengen scanner — compliance mapping

Each detector is cross-referenced to the controls that auditors commonly
ask for. Pass `--compliance` to `tengen scan` (any format) and each
finding in the output gets annotated with the mappings below.

**What this is:** a cheat-sheet auditors can tick against.
**What this is NOT:** a certification. Running `tengen scan` does not
make you SOC 2 compliant; it helps you answer "do you scan your code
for common vulnerabilities?" with evidence.

---

## Reference tables

### Mapping per detector

| Detector ID | OWASP Top 10 (2021) | CWE | SOC 2 TSC | ISO/IEC 27001:2022 |
|---|---|---|---|---|
| `SQLI-TEMPLATE` | A03 Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | CC6.1 | A.8.28 Secure coding |
| `EVAL` | A03 Injection | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | CC6.1 | A.8.28 Secure coding |
| `INNERHTML` | A03 Injection (XSS) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | CC6.1 | A.8.28 Secure coding |
| `DANGEROUSLY-SET-INNERHTML` | A03 Injection (XSS) | CWE-79 | CC6.1 | A.8.28 Secure coding |
| `HARDCODED-SECRET` | A07 Identification & Authentication Failures | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | CC6.1 | A.8.24 Use of cryptography |
| `JWT-HARDCODED-SECRET` | A02 Cryptographic Failures | CWE-798 | CC6.1 | A.8.24 Use of cryptography |
| `MATH-RANDOM-SECURITY` | A02 Cryptographic Failures | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | CC6.7 | A.8.24 Use of cryptography |
| `JSON-PARSE-REQUEST` | A03 Injection | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | CC6.1 | A.8.28 Secure coding |
| `OPEN-REDIRECT` | A01 Broken Access Control | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | CC6.1 | A.8.28 Secure coding |
| `CORS-WILDCARD-CREDENTIALS` | A05 Security Misconfiguration | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | CC6.1 | A.5.14 Information transfer |
| `EXPOSED-ENV-CLIENT` | A05 Security Misconfiguration | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | CC6.1 | A.8.2 Privileged access rights |

### Reverse lookup

#### SOC 2 controls touched by Tengen

- **CC6.1** Logical access security — covers 10/11 detectors (broadly, "did you protect your code against common vulnerabilities?").
- **CC6.7** Restricts logical access to credentials — covers the cryptographic-randomness detector.

#### ISO/IEC 27001:2022 Annex A controls touched

- **A.5.14** Information transfer — CORS misconfiguration.
- **A.8.2** Privileged access rights — client-exposed server env.
- **A.8.24** Use of cryptography — randomness + hardcoded keys + JWT secrets.
- **A.8.28** Secure coding — the application-layer injection/XSS class.

#### OWASP Top 10 (2021) coverage

- A01 Broken Access Control — open redirect
- A02 Cryptographic Failures — JWT secret, Math.random
- A03 Injection — SQLi, eval, XSS, unvalidated JSON
- A05 Security Misconfiguration — CORS, exposed env
- A07 Identification & Auth Failures — hardcoded secrets

A04, A06, A08, A09, A10 are not covered by Tengen regex-level checks;
you need an SAST (e.g., Semgrep, CodeQL) and a DAST (e.g., ZAP,
Burp) to cover them meaningfully.

---

## Auditor evidence package

If your auditor asks "show me your SAST coverage," here is a minimum
evidence pack you can assemble from what Tengen produces:

1. **The policy**: a short page explaining that every PR to `main`
   runs `tengen scan --fail-on high --compliance` and cannot merge on
   critical/high findings. (Your GitHub Action status check is the
   enforcement.)
2. **A recent clean run**:
   ```bash
   npm run tengen -- scan . --format html --compliance > tengen-scan.html
   ```
   Archive `tengen-scan.html` + the commit SHA.
3. **The SBOM** (auditors love SBOMs):
   ```bash
   npm run sbom
   ```
   Output is `sbom.json` in CycloneDX 1.x format.
4. **The policy for handling findings**: a note describing how long
   your team has to remediate by severity (e.g., critical: 24h, high:
   7d, medium: 30d).
5. **The ignore file**: `.tengenignore` with comments explaining why
   specific findings were accepted. Auditors want to see that the
   decision is documented, not that the finding is gone.

---

## Ignore file format

Create `.tengenignore` at the root of your project. The scanner
auto-discovers it (or pass `--ignore <path>` for a different location).

```
# Format: <detector-id>:<file-regex>    or just <detector-id>
# Regex is anchored to the start of the relative path.

# Specific file, specific rule.
HARDCODED-SECRET:src/fixtures/test-keys.ts

# Specific rule, everywhere under a directory.
MATH-RANDOM-SECURITY:src/ui/animations/

# Suppress an entire rule project-wide (DISCOURAGED).
OPEN-REDIRECT

# Wildcard rule: suppress all detectors in a specific directory.
*:vendor/

# Blank lines and #-comments are ignored.
```

Every ignore entry should carry a one-line comment explaining *why*
the finding is accepted. Auditors who read this file are happier when
reasoning is explicit.

---

## Gate strictness presets

Pick the `--fail-on` level by environment:

| Environment | `--fail-on` | Rationale |
|---|---|---|
| Local dev (pre-commit) | `critical` | Don't block hot work on medium findings. |
| Pull request CI | `high` | Default. Blocks anything auditor-meaningful. |
| Pre-release gate | `medium` | Higher bar before tagging a release. |
| Production monitoring | `low` | Any regression is a ticket. |

---

## What auditors actually ask for (observed from SOC 2 Type II prep)

1. "Show me a sample scan output, dated and signed to a commit."
2. "Show me that the scan runs on every PR."
3. "Show me your ignore file and the reasoning."
4. "Show me your remediation timeline policy by severity."
5. "Show me that you update the scanner / ruleset periodically."

Tengen + GitHub Actions + the templates in this repo give you
evidence for all 5.
