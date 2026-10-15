# Severity rubric

Severity = how bad it is **if real**. Confidence (CONFIRMED / LIKELY / NOT_CONFIRMED /
INCONCLUSIVE) = how sure we are that it is real. They are always rated separately.

| Severity | Rule | Typical examples |
|----------|------|------------------|
| **Critical** | An unauthenticated or low-privilege attacker can take over accounts, the server, or all data with little effort. | Auth bypass, SQL injection on login, RCE, admin takeover |
| **High** | An attacker can read or change other users' sensitive data or perform privileged actions. | IDOR on personal data, missing auth on a sensitive route, stored XSS, hardcoded JWT secret |
| **Medium** | Real weakness, but needs extra conditions or has limited impact. | No login rate limit, CSRF on a low-impact action, weak cookie flags, account enumeration |
| **Low** | Hardening gap with little direct impact on its own. | Missing Referrer-Policy, server banner leaked, verbose but harmless errors |
| **Info** | An observation with no security impact by itself. | Detected framework, route inventory, check skipped |

Rules of thumb:
- A missing control is a finding to review, not automatically an exploitable bug (Rule 6).
- If two reviewers would argue between two levels, pick the lower one and say why in the description.
- `CONFIRMED` is only allowed when there is saved request/response evidence (Rule 2).
