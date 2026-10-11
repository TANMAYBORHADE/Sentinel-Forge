# SentinelForge: Full Build Roadmap

**Tagline:** Find it. Prove it. Report it.

**What it is:** a personal security scanner that looks at a web app (source code plus the running local copy), tests it, and reports which security problems are real, with proof.

**Stack:** Python 3 (CLI) · `requests` / `httpx` for live checks · SQLite for scan history · Semgrep, gitleaks, `npm audit` / `pip-audit` for code scanning · Docker for the sandbox · optional LLM for explanations (later)

**First test targets:** deliberately vulnerable apps (OWASP Juice Shop, crAPI, DVWA) to prove the scanner works, then Sanjeevani as the first real project.

**Rule for every phase:** don't move to the next one until the current one is actually tested against a real running app, not just "written."

**Safety rules (never break these):**
- Only scan apps you own, running locally or in a test environment you control. Never a live site, never someone else's.
- The scanner never edits the app's source code. It only reads code and sends test requests.
- Heavy or destructive tests (big uploads, flooding, zip bombs) are off by default and must be opted into.

**Legend:** 🟢 easy · 🟡 medium · 🔴 harder

---

## Phase 1: Foundation (CLI, targets, results)

- [ ] Create repo structure: `sentinelforge/` with `cli.py`, `checks/`, `lib/`, `reports/`, `tests/`
- [ ] `cli.py`: `python sf.py scan --url http://localhost:5000 --src ./myapp`
- [ ] Define the **finding model**: `id`, `title`, `category`, `severity`, `confidence`, `status`, `evidence`, `endpoint`, `file`, `line`, `fix`
- [ ] Define statuses: `PASS`, `FAIL`, `WARN`, `SKIPPED`, `ERROR`
- [ ] Define confidence levels: `CONFIRMED` · `LIKELY` · `NOT_CONFIRMED` · `INCONCLUSIVE` (separate from severity)
- [ ] Severity rubric written down once: Critical / High / Medium / Low / Info, with a one-line rule for each so ratings stay consistent
- [ ] Target allowlist: refuse to run unless the host is `localhost`, `127.0.0.1`, or one you listed in `config.yaml`
- [ ] `config.yaml`: base URL, login route, test users, upload route, check groups to run/skip
- [ ] `lib/http.py`: request wrapper that records the full request and response as evidence
- [ ] SQLite storage: `scans`, `findings` tables
- [ ] Stable **finding fingerprint** (check id + endpoint + location) so the same issue is recognised across scans
- [ ] Console report with ✅ ❌ ⚠️ and a summary line

**Checkpoint:** `python sf.py scan --url http://localhost:5000` runs, refuses non-local targets, and saves an (empty) scan to the database.

---

## Phase 2: Project understanding (ingest and detect)

- [ ] 🟢 Walk the source folder and ignore `node_modules`, `.git`, build folders
- [ ] 🟢 Detect languages (by file extension counts)
- [ ] 🟢 Detect frameworks (Express, Next.js, Flask, FastAPI, Django, Spring...) from `package.json`, `requirements.txt`, imports
- [ ] 🟢 Detect package managers and lockfiles
- [ ] 🟢 Detect databases and ORMs (Prisma, SQLAlchemy, Mongoose...)
- [ ] 🟢 Detect Docker, CI files, `.env` files, config files
- [ ] 🟡 **API discovery:** read OpenAPI/Swagger if present
- [ ] 🟡 **API discovery:** parse framework routes (Express `app.get/post`, Flask `@app.route`, FastAPI decorators)
- [ ] 🟡 Record per route: method, path, params, auth middleware present or missing
- [ ] 🔴 Runtime crawl: hit common paths and links to find routes not found in code
- [ ] 🟢 Print a short "what is this app" summary at the start of every scan

**Checkpoint:** SentinelForge can point at a project and print its stack and a list of every route with its auth status.

---

## Phase 3: Code scanning (orchestrate existing tools)

Don't rebuild these tools. Run them, normalise their output into your finding model, and de-duplicate.

- [ ] 🟢 Run **gitleaks** (or regex fallback) for secrets and convert results
- [ ] 🟢 Run **Semgrep** with security rule packs and convert results
- [ ] 🟢 Run **`npm audit`** / **`pip-audit`** / OSV-Scanner for vulnerable dependencies
- [ ] 🟢 Never print real secret values in any report (show file, line and type only)
- [ ] 🟢 De-duplicate findings from different tools that point to the same line
- [ ] 🟢 Map each finding to a CWE and OWASP category

**Custom checks (small, project-aware rules):**
- [ ] 🟢 Password hashing: bcrypt / argon2 / scrypt = PASS; md5, sha1, plain sha256, plaintext = FAIL
- [ ] 🟢 Bcrypt cost factor too low
- [ ] 🟢 Weak random for tokens/OTPs (`Math.random`, `random.random`) instead of `crypto` / `secrets`
- [ ] 🟢 Hardcoded JWT secret or encryption key
- [ ] 🟢 `.env` committed or missing from `.gitignore`
- [ ] 🟡 Secrets present in Git history
- [ ] 🟢 `DEBUG=True` / verbose errors left on
- [ ] 🟢 No lockfile
- [ ] 🟢 `eval`, `exec`, `new Function`, `os.system`, `subprocess(shell=True)`
- [ ] 🟡 SQL built by string concatenation or f-strings; raw query functions
- [ ] 🟢 `pickle.loads`, `yaml.load` on untrusted input
- [ ] 🟡 `innerHTML`, `dangerouslySetInnerHTML`, `|safe`
- [ ] 🟡 Routes with an `:id` param but no ownership check
- [ ] 🟡 Routes missing auth middleware
- [ ] 🟡 Request body spread straight into DB create/update (mass assignment)
- [ ] 🟢 Secrets in `NEXT_PUBLIC_*` or other client-exposed variables
- [ ] 🟡 Password hash or token fields returned in responses

**Checkpoint:** one command scans the source and produces a de-duplicated list of findings with file and line, no live app needed.

---

## Phase 4: Auth and session checks (live)

Needs two or more seeded test users per role (see Phase 8 setup notes).

**Login and registration**
- [ ] 🟢 **Login limiter:** ~20 wrong passwords, PASS only if blocked (429 / lockout)
- [ ] 🟢 **Signup limiter:** many registrations quickly
- [ ] 🟢 **Limiter scope:** per IP and per account (credential stuffing)
- [ ] 🟢 **Account enumeration (message):** different errors for "no user" vs "wrong password"
- [ ] 🟢 **Account enumeration (timing):** response time differs for existing vs missing users
- [ ] 🟢 **Weak passwords accepted:** `123456`, `a`
- [ ] 🟢 **Signup privilege escalation:** `role: admin`, `isAdmin: true` in the registration body
- [ ] 🟡 Password change requires the old password
- [ ] 🟡 **Password reset:** unlimited reset requests, guessable or non-expiring tokens, token reuse
- [ ] 🟡 **OTP / MFA:** attempt limit exists and can't be brute-forced
- [ ] 🟡 OAuth / social login: forged token accepted, account takeover through email linking

**Sessions and tokens**
- [ ] 🟡 **Logout invalidates** the old session/token
- [ ] 🟡 **Session fixation:** session ID changes after login
- [ ] 🟡 **Idle and absolute timeout** exist
- [ ] 🟡 **JWT expiry** exists and is reasonable (WARN on very long lifetimes)
- [ ] 🟡 **JWT `alg: none`** rejected
- [ ] 🟡 **JWT tampering:** changed payload with old signature rejected
- [ ] 🟡 **JWT weak secret:** try a short list of common secrets
- [ ] 🟡 Refresh token reuse after rotation
- [ ] 🟢 Tokens stored in `localStorage` (WARN, reachable by XSS)
- [ ] 🟢 Cookie flags: `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`

**Checkpoint:** SentinelForge proves, with request and response, whether accounts can be brute-forced, enumerated, or hijacked.

---

## Phase 5: Authorization checks (live, highest value)

- [ ] 🟡 **Missing auth:** call every discovered route with no token and list those that respond
- [ ] 🟡 **IDOR:** User A requests User B's resource by changing the ID
- [ ] 🟡 **IDOR in the request body:** swap `userId` / `orgId` / owner IDs, not just URL IDs
- [ ] 🟡 **Role bypass:** normal user calls admin routes
- [ ] 🟡 **Horizontal escalation** (same role, other user) and **vertical escalation** (higher role) reported separately
- [ ] 🟡 **Mass assignment:** `role`, `isVerified`, `ownerId`, price fields in create/update bodies
- [ ] 🟡 **Identity spoofing:** server must trust the token, not an ID or email sent by the client
- [ ] 🟡 **Revoked user:** old token still works after the account is disabled
- [ ] 🟡 **Route × role matrix:** every route tested with every role, printed as a table
- [ ] 🟢 **Predictable IDs:** sequential IDs allow easy enumeration (WARN)
- [ ] 🟡 Tenant isolation: users of one org can't read another org's data
- [ ] 🟡 Function-level authorization on write routes (create, update, delete)
- [ ] 🟡 Sensitive fields leaking in responses (excessive data exposure)

**Checkpoint:** a route-by-role matrix with every unexpected "allowed" highlighted and backed by evidence.

---

## Phase 6: Web, API and injection checks (live)

**Headers and browser security**
- [ ] 🟢 `Content-Security-Policy`
- [ ] 🟢 `X-Frame-Options` / `frame-ancestors` (clickjacking)
- [ ] 🟢 `X-Content-Type-Options`
- [ ] 🟢 `Strict-Transport-Security`
- [ ] 🟢 `Referrer-Policy`
- [ ] 🟢 CORS: `*`, reflected origins, or credentials allowed with wildcard
- [ ] 🟢 Server / framework banner leaked
- [ ] 🟡 CSRF: state-changing requests accepted without token or origin check (only if cookie auth is used)
- [ ] 🟡 Open redirect (`?next=`, `?redirect=`)
- [ ] 🟡 SSRF: any feature that fetches a URL you supply

**API hygiene**
- [ ] 🟢 General rate limiting on an expensive route
- [ ] 🟢 Pagination caps (`?limit=1000000`, negative, non-numeric)
- [ ] 🟢 Oversized JSON body rejected
- [ ] 🟢 Very long strings in fields (1 MB+)
- [ ] 🟡 Deeply nested JSON
- [ ] 🟡 Type confusion (arrays/objects where strings are expected)
- [ ] 🟢 Undocumented routes: `/swagger`, `/api-docs`, `/graphql`, `/debug`
- [ ] 🟢 Unexpected HTTP methods (`PUT`, `DELETE`, `TRACE`)

**Injection**
- [ ] 🟡 SQL injection: `'` and `' OR '1'='1` in inputs and look for errors or changed behavior
- [ ] 🟡 NoSQL injection (`{"$gt": ""}`)
- [ ] 🟡 Command injection (harmless marker commands only)
- [ ] 🟡 Reflected XSS with a harmless marker payload
- [ ] 🟡 Stored XSS: submit a marker, then check how it renders
- [ ] 🟡 Path traversal (`../../etc/passwd` on your local copy)
- [ ] 🟡 Prototype pollution (`__proto__` keys, Node only)
- [ ] 🟡 ReDoS: crafted long strings against regex-validated fields
- [ ] 🔴 Unsafe deserialization
- [ ] 🔴 Template injection

**Checkpoint:** the scanner sends hostile and malformed input to every route and records what breaks.

---

## Phase 7: File upload checks (your "file bomb" idea)

Auto-detect upload routes from Phase 2, or set them in `config.yaml`. Use harmless test files only.

- [ ] 🟢 **Max file size:** 50 MB first, bigger only with `--heavy`
- [ ] 🟢 Max request size and number of files per request
- [ ] 🟢 Unexpected field names don't crash the server
- [ ] 🟢 **Extension allowlist:** `.php`, `.html`, `.exe`, `.svg`, `.js`
- [ ] 🟢 **Fake extension:** text file renamed `.jpg` / `.pdf`
- [ ] 🟢 **Magic-byte validation**
- [ ] 🟢 **Double extension:** `file.jpg.php`
- [ ] 🟡 **Filename traversal:** `../../x.txt`, null bytes
- [ ] 🟡 **Zip bomb** (small archive that expands hugely, `--heavy` only, local only)
- [ ] 🟡 **Zip slip:** archive entries with `../`
- [ ] 🟢 HTML / SVG upload served inline and executing in the browser
- [ ] 🟢 Upload rate limit (100 uploads in a row)
- [ ] 🟡 Public exposure: uploaded files reachable without login
- [ ] 🟡 Processing timeout: a huge or complex file doesn't hang the server
- [ ] 🟡 Disk exhaustion: no per-user storage cap
- [ ] 🟡 Memory vs disk storage: large files held in RAM
- [ ] 🟡 Image metadata (EXIF / GPS) stripped
- [ ] 🟡 Uploading to a resource the user doesn't own

**Checkpoint:** every bad file is uploaded and the report shows exactly which ones the server accepted.

---

## Phase 8: Verification engine and test environment

This is the hardest part of the project. Build it carefully.

- [ ] 🟡 `sf env up`: start the target app locally (Docker Compose or a run command from `config.yaml`)
- [ ] 🟡 Seed script support: create test users and test data per role
- [ ] 🟡 Health check: wait until the app responds before testing
- [ ] 🟡 State reset between risky tests (reset DB or re-seed)
- [ ] 🟡 Define three **verification types:**
  - **Static proof:** confirmed from code or config (e.g. hardcoded secret)
  - **Config proof:** confirmed from headers or settings
  - **Dynamic proof:** confirmed by a real request and response
- [ ] 🟡 Every FAIL stores the request, response snippet and a **replay command** (curl)
- [ ] 🟡 A finding that can't be verified is labelled `INCONCLUSIVE`, never `CONFIRMED`
- [ ] 🟡 Failed verification marks a finding `NOT_CONFIRMED` and keeps the evidence of why
- [ ] 🟡 Kill switch: Ctrl+C stops all running tests cleanly
- [ ] 🟡 Request rate cap so the scanner can't accidentally flood the target
- [ ] 🟡 Sandbox: no access to the host filesystem or other networks beyond the target

**Checkpoint:** SentinelForge starts a target, seeds it, runs verified checks, and cleans up, with no manual steps.

---

## Phase 9: Errors, leaks, logging and privacy

- [ ] 🟢 Stack traces shown on malformed input
- [ ] 🟢 SQL errors, file paths, internal IPs in error responses
- [ ] 🟢 Framework or version in headers and error pages
- [ ] 🟢 Exposed paths: `/.env`, `/.git/config`, `/package.json`, `/backup.zip`
- [ ] 🟢 Source maps publicly served (`*.map`)
- [ ] 🟢 Directory listing enabled
- [ ] 🟢 Passwords, tokens, hashes in API responses
- [ ] 🟡 Debug or health routes that reveal config
- [ ] 🟢 Failed logins are logged
- [ ] 🟢 Admin actions and password changes are logged
- [ ] 🟡 Passwords, tokens and API keys never appear in logs
- [ ] 🟢 Sensitive data in URLs (tokens in query strings)
- [ ] 🟡 API returns more personal data than needed
- [ ] 🟡 Account deletion actually deletes data
- [ ] 🟡 Unbounded or expensive DB queries

**Checkpoint:** you know exactly what the app leaks through errors, logs and responses.

---

## Phase 10: Business logic and abuse

- [ ] 🟡 Race condition: same one-time action (coupon, invite, vote) sent twice at once
- [ ] 🟡 Repeat of one-time actions (double submit, double refund)
- [ ] 🟡 Workflow skipping: jumping to a later state without earlier steps
- [ ] 🟡 Negative, zero, huge or decimal values in quantity and price fields
- [ ] 🟡 Impossible dates and coordinates
- [ ] 🟡 Invite / reset token reuse
- [ ] 🟢 Spam: bulk account creation
- [ ] 🟡 OTP and password-reset abuse
- [ ] 🟡 Expensive endpoint abuse
- [ ] 🟡 Many concurrent requests: server slows or crashes
- [ ] 🟡 Template library for common logic flaws (reusable test patterns)
- [ ] 🔴 User-supplied "intended behavior" notes the scanner can test against

**Checkpoint:** you know which flows can be repeated, reordered, or raced.

---

## Phase 11: Reporting

- [ ] Report sections: Summary · Architecture · Threat model · Confirmed findings · Unconfirmed findings · Recommendations
- [ ] Group findings by severity, then by confidence
- [ ] Each finding shows: title, endpoint/file, description, evidence, impact, fix
- [ ] Outputs: console, **HTML**, **JSON**, **Markdown**
- [ ] **SARIF export** so findings show up in GitHub / VS Code
- [ ] Secrets are always masked
- [ ] Don't use a single "security score" as the headline. If you add one, show the breakdown beside it, and always show Critical issues first
- [ ] Short threat model section: assets, actors, trust boundaries (auto-filled from Phase 2, edited by hand)

**Checkpoint:** one command produces a readable report someone else could act on.

---

## Phase 12: History and comparison

- [ ] Save every scan with timestamp and tool version
- [ ] Finding lifecycle: `DISCOVERED` → `TRIAGED` → `VERIFIED` / `NOT_CONFIRMED` / `INCONCLUSIVE` → `REPORTED`
- [ ] Extra states: `FIXED`, `REGRESSED`, `SUPPRESSED`, `ACCEPTED_RISK`
- [ ] `sf compare scan1 scan2`: New · Fixed · Still open · Regressed
- [ ] Suppress a finding with a written reason
- [ ] Show trend over time (findings per scan)

**Checkpoint:** you can see whether your app is getting more secure over time.

---

## Phase 13: Measure that it works (evaluation)

- [ ] Run against OWASP Juice Shop, crAPI, DVWA, VAmPI
- [ ] Write down which known vulnerabilities each target has
- [ ] Track **detected** vs **missed** (recall) and **false alarms** (precision)
- [ ] Record scan time and (if AI is used) cost per scan
- [ ] Re-run the benchmark after every major change and compare
- [ ] Keep a regression test per check (a vulnerable sample and a fixed sample)

**Checkpoint:** you have numbers showing the scanner finds real problems and doesn't cry wolf.

---

## Phase 14: AI assistance (only after the above works)

- [ ] Model-agnostic wrapper so the AI provider can be swapped
- [ ] AI explains each confirmed finding in plain language and suggests a fix
- [ ] AI triages tool output: likely false positives, duplicates
- [ ] AI proposes extra authorization and logic tests from the route map
- [ ] **AI output is a hypothesis.** Only a verified test can mark something `CONFIRMED`
- [ ] Redact secrets before sending any code to a model
- [ ] Treat repo content as untrusted: the AI gets no tools that can send data out, and instructions inside code comments are ignored
- [ ] Log model name and prompt version per finding so results are reproducible

**Checkpoint:** AI makes reports clearer and finds extra leads, without ever being the source of truth.

---

## Phase 15: Production readiness (later, optional)

- [ ] Basic load test with k6 (10 → 50 → 100 → 250 users, stop at a threshold)
- [ ] Record p50 / p95 / p99 latency, error rate, requests per second
- [ ] Identify the first bottleneck (DB pool, CPU, memory)
- [ ] Report as "capacity of the **tested environment**," never as a production guarantee
- [ ] Stress test: what happens past the limit, and does it recover?
- [ ] Resilience: stop DB / Redis / external API and observe behavior
- [ ] Production config review: timeouts, health checks, graceful shutdown, resource limits

**Checkpoint:** you know where your app starts to struggle and what breaks first.

---

## Phase 16: Continuous use (future)

- [ ] Git hook or CI job that runs the fast checks on every push
- [ ] Pull-request summary of new findings
- [ ] Scheduled scans
- [ ] Alert when a previously fixed finding regresses

**Checkpoint:** SentinelForge runs by itself and tells you when something new breaks.

---

## First 15 checks to build (priority order)

1. Login limiter
2. Signup role escalation
3. Cookie flags and token storage
4. Security headers and CORS
5. Upload size limit
6. Fake extension and magic bytes
7. Hardcoded secrets and `.env` committed
8. Password hashing and cost factor
9. Missing auth on every route
10. IDOR
11. Role bypass on admin routes
12. Mass assignment
13. Account enumeration
14. Password reset token and expiry
15. Stack traces and exposed paths

---

## Explicitly out of scope for now

- Automatic code fixing, commits, or deployments
- Changing any infrastructure or production system
- Destructive or unrestricted exploitation
- Cloud/IAM, container and CI/CD audits
- Malware scanning of uploads
- Malicious package and typosquatting detection (use `npm audit` / `pip-audit`)
- Request smuggling, CRLF injection
- Multi-agent "security team" setup (start with a single pipeline)

---

## Fundamental rules

1. Never modify the user's source code.
2. Never call a finding `CONFIRMED` without saved evidence.
3. Keep severity and confidence separate.
4. Never print real secret values in any report.
5. Frontend checks are never a substitute for server-side checks.
6. A missing control is a finding to review, not automatically an exploitable bug.
7. Only test systems you own, and never production.
8. Prefer evidence over AI reasoning.
9. Keep complete history of every scan.
10. Every finding must say what to fix.
