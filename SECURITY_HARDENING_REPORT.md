# Lodge Matariki 476 security hardening report

Branch: `security-playwright-hardening`  
Baseline: `0d7a56249d6ae0b35734a4258253b01a5422a0bc`

## Executive summary

The baseline contained several high-impact risks: committed email/application credentials, automatically active public registrations, a static-path bypass for member documents, missing per-file audience checks, legacy fast password hashes with a shared salt, no CSRF enforcement, no login throttling, and deployment without a test gate.

This branch implements defense in depth while preserving the deployed `main` branch. Existing legacy password records remain usable: after the first successful login they are immediately rehashed with scrypt.

## Implemented controls

| Area | Control |
|---|---|
| Authentication | Scrypt password hashes, constant-time legacy verification and automatic migration, 12-character password policy, session renewal on login, POST-only logout, ten-minute sessions |
| Registration | Public accounts are created inactive and require administrator approval; only an authenticated administrator can create an active account or assign the admin role |
| Revocation | Every authenticated request refreshes role/active status from PostgreSQL, so deactivation and role changes invalidate existing privileges immediately |
| Password reset | Random 256-bit token; only SHA-256 digest stored; one-hour expiry; generic account-enumeration-safe response; throttled requests |
| Request integrity | CSRF protection on every state-changing form; 10 MB request cap; strict server-side length, date, time, role and audience validation |
| Abuse controls | Login, registration, password-reset and contact-form rate limits; contact-form honeypot |
| File security | Protected document and profile-image folders outside static assets; public legacy paths blocked; content/extension verification; randomized stored names; per-record role/audience authorization; safe deletion; attachment response |
| Event security | Admin-only event filtering is enforced for member ICS and Google Calendar routes; member read markers cannot target admin-only events; ICS inputs are handled only after authorization |
| Browser security | CSP, anti-framing, MIME sniffing prevention, HSTS on HTTPS, strict referrer policy, restricted browser permissions, secure/HttpOnly/SameSite cookies |
| Database | Parameterized SQL retained throughout; active-account checks; connection timeouts; TLS required for `DATABASE_URL` cloud connections |
| Supply chain | Vulnerable Flask, Werkzeug, Click and python-dotenv versions upgraded; `pip-audit` and Bandit run in CI |
| Containers | Non-root runtime user, secret-free Compose file, health-checked PostgreSQL, private persistent volumes, reduced Docker build context |
| CI evidence | A separate security workflow runs on pushes and pull requests; production deployment remains unchanged pending explicit owner approval |

## Automated evidence

Local checks completed:

- 17 unit/application security tests passed;
- all 20 Jinja templates compiled;
- Python compilation passed;
- Bandit reported no medium/high findings;
- `pip-audit` reported no known vulnerabilities after dependency upgrades.

The GitHub workflow provisions PostgreSQL 16, creates only synthetic accounts/data, starts Gunicorn, installs Chromium and runs six Playwright end-to-end scenarios:

1. anonymous, inactive member, active member and admin authorization boundaries;
2. public registration remains pending until admin approval;
3. member document visibility/download and admin-only denial;
4. member event visibility plus admin-only ICS/Google denial;
5. admin event creation, XSS-safe rendering and validated file upload;
6. CSRF rejection, security headers, static-path blocking and immediate session revocation.

Failure runs retain the application log, screenshot and Playwright trace for 14 days.

## Mandatory actions outside this branch

These operations cannot be completed safely by source-code changes:

1. Rotate the Gmail app password and the exposed Flask secret immediately. Treat both as compromised because they remain in Git history.
2. Remove the exposed secrets from repository history using an approved history-rewrite procedure, then invalidate old clones as appropriate.
3. Review the documents currently committed under `app/static/files` and unreferenced PDF/DOC files under `app/static/img`. They are excluded from new Docker images and blocked at runtime by this branch, but public Git history must be treated as already disclosed.
4. Back up current production uploads and migrate them to a private persistent Azure storage mount before deploying this branch. Set `FILE_UPLOAD_FOLDER` to that mount.
5. Configure production settings: `APP_ENV=production`, a new 32+ character `SECRET_KEY`, `SESSION_COOKIE_SECURE=1`, `TRUSTED_HOSTS`, database TLS settings and a shared `RATELIMIT_STORAGE_URI`.
6. Protect `main` and require the **Security and end-to-end tests / verify** check before merge. If you want the Azure deployment workflow itself to depend on this check, approve that production-workflow change separately.

## Scope note

Passing tests materially reduces known risk but is not a guarantee of absolute security. Azure identity/access policies, database firewall rules, storage ACLs, backups, monitoring, incident response and secret rotation must also be reviewed in the Azure tenant.
