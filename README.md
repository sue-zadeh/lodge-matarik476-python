# Lodge Matariki 476 portal

Flask, Jinja, PostgreSQL, Docker, Playwright and GitHub Actions, deployed to Azure App Service.

## Safe local setup

1. Install Docker Desktop or Docker Engine with Compose.
2. Copy `.env.example` to `.env` and replace every placeholder. Generate a secret with `python -c "import secrets; print(secrets.token_hex(32))"`.
3. Start the application and database:

   ```bash
   docker compose up --build
   ```

4. For a new database only, create the first administrator interactively:

   ```bash
   docker compose exec web python scripts/create_admin.py
   ```

5. Open <http://localhost:8000>.

Public registrations are deliberately inactive until an administrator activates them from **Manage Users**.

## Verification

Install development dependencies and Chromium, then run the unit/security suite:

```bash
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
python -m pytest -m "not e2e"
python -m pip_audit -r requirements.txt
python -m bandit -q -ll -r app connect.py run.py hash_password.py -x tests
```

The full PostgreSQL + Playwright suite is reproducibly executed by `.github/workflows/security.yml` on every branch push and pull request. Configure GitHub branch protection to require its `verify` job before merging to `main`. The existing Azure deployment workflow is intentionally unchanged by this branch.

## Production requirements

Read [SECURITY.md](SECURITY.md), [SECURITY_HARDENING_REPORT.md](SECURITY_HARDENING_REPORT.md), and [AZURE_DEPLOYMENT_CHECKLIST.md](AZURE_DEPLOYMENT_CHECKLIST.md) before deployment. In particular, rotate previously committed credentials, apply the password-reset migration, use a private persistent Azure storage mount for `FILE_UPLOAD_FOLDER`, configure a shared rate-limit backend and require the security workflow before merging to `main`.
