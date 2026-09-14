# Azure deployment checklist

Do not place an Outlook, Gmail, database, or application password in this repository.

## 1. Back up production

- Back up the Azure PostgreSQL database.
- Back up existing member documents and profile images.
- Confirm the protected Azure storage mount before deploying the security branch.

## 2. Apply the Forgot Password migration

From a trusted machine with `psql` and the production `DATABASE_URL` configured:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f migrations/20260902_add_password_reset_columns.sql
```

Verify it:

```sql
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'users'
  AND column_name IN ('password_reset_token', 'password_reset_token_expiry')
ORDER BY column_name;
```

The migration is idempotent, so running it again does not duplicate the columns.

## 3. Configure Azure App Settings

Set these in **Azure Portal → App Service → Environment variables**:

```text
APP_ENV=production
CONTACT_EMAIL=lodgematariki476@outlook.com
EMAIL_USER=<technical email sender>
EMAIL_PASS=<new rotated sender credential>
EMAIL_SUPPRESS_SEND=0
PUBLIC_BASE_URL=https://<the real Lodge website hostname>
SECRET_KEY=<new random value of at least 32 characters>
SESSION_COOKIE_SECURE=1
TRUSTED_HOSTS=<the real Lodge hostname>
```

`CONTACT_EMAIL` is the Outlook inbox receiving Contact Us messages. Its Outlook password is not required. `EMAIL_USER` is only the authenticated technical sender used by the current SMTP integration.

Do not use an Outlook password or app password as a new SMTP shortcut. If Outlook must also become the sender, add Microsoft OAuth2/Graph as a separate reviewed change.

## 4. Deploy and smoke-test

1. Require the green **Security and end-to-end tests / verify** check.
2. Review and merge the security pull request.
3. Confirm Azure deploys the new `main` image.
4. Submit one Contact Us message and confirm it arrives at `lodgematariki476@outlook.com`.
5. Request one password-reset email for a test member, use the link once, and confirm it cannot be reused.
6. Confirm member-only files remain private in an incognito browser.

Never test these flows with real member data unless necessary and approved.
