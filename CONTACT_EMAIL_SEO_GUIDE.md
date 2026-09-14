# Contact form, reset email and Google setup

## Change the appearance

- `app/templates/base.html`: find `.contact-details a`. `color: #fff` makes the email white; `font-size: 0.95em` makes it slightly smaller than the surrounding contact details. The hover rule also stays white.
- `app/templates/contact.html`: the heading uses `class="display-5 fw-normal mb-4"`. Bootstrap's `fw-normal` means weight 400. `fw-400` is not a built-in Bootstrap class. Use `fw-medium` for 500 if you later want a stronger heading.
- `app/__init__.py`: `CONTACT_MESSAGE_MAX_LENGTH=500` controls both server validation and the textarea's maximum and helper text. The counter reads the textarea's maximum automatically.

500 characters keeps enquiries brief. The text itself is small; reducing it is unlikely to noticeably change the Azure bill. Request volume, hosting plan, database/storage usage and email provider pricing matter more. Existing spam protection, contact rate limits and message retention remain in place; this change does not delete existing messages or add a paid service.

## Why reset email could fail

The old reset function used Gmail STARTTLS on port 587, while the working contact form used Gmail SSL on port 465. Both now use the same verified TLS connection on port 465, with a 10-second socket timeout. Reset tokens are committed to the database before sending the email.

This resolves the inconsistent code paths, but does not prove that port 587 was the cause on your Azure account. Missing reset columns, disabled sending, missing credentials, an incorrect member email, or a pending/inactive account can also prevent delivery. The public form intentionally gives the same response for registered and unregistered addresses.

Contact messages go to `CONTACT_EMAIL`. Reset messages go to the email saved on that active member's account. Both are sent using the Gmail `EMAIL_USER` and `EMAIL_PASS`; the Outlook inbox password is not used.

## Check email locally (Ubuntu)

From the project folder, activate your existing virtual environment:

```bash
source venv/bin/activate
python -m flask --app run mail-check --check-smtp
```

This checks configuration, reset columns, and SMTP login. It does not send an email and does not print the sender password or member data.

If you run the application with Docker Compose, use this instead:

```bash
docker compose exec web flask --app run mail-check --check-smtp
```

For a missing setting, edit your local `.env` (never commit it). For Azure, edit App Service environment variables. Keep `EMAIL_SUPPRESS_SEND=0` for real email delivery.

If Flask runs at `http://127.0.0.1:5000`, leave `PUBLIC_BASE_URL` blank locally, or set it to that exact URL. A stale `http://localhost:8000` value creates links to the wrong port. In Azure, set `PUBLIC_BASE_URL=https://lodgematariki476.co.nz`.

If Flask runs directly in Ubuntu and PostgreSQL runs in the repository's Docker Compose configuration, the database connection is `DB_HOST=127.0.0.1`, `DB_PORT=5434`. Inside the web container, it is `DB_HOST=db`, `DB_PORT=5432`. These values may differ if you have your own local Compose override.

If the command reports missing reset columns, back up the database and run the existing migration against the correct database. For the local Compose database:

```bash
docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' < migrations/20260902_add_password_reset_columns.sql
```

For Azure PostgreSQL, follow `AZURE_DEPLOYMENT_CHECKLIST.md`. Restarting the web app does not add database columns. Do not run `database.psql`, test seeds, or `docker compose down -v` against an existing member database to fix this problem.

After the checks pass, request one reset using the exact email saved on your active test member. Check spam/junk too. Use the delivered link once, then verify it cannot be reused. A successful SMTP login alone does not prove inbox delivery.

## Google setup after deployment

The code now provides unique public-page descriptions, stable HTTPS canonical URLs, page-specific sharing tags, a homepage H1, Organization structured data using existing lodge details, and these endpoints:

- Sitemap: https://lodgematariki476.co.nz/sitemap.xml
- Crawler guidance: https://lodgematariki476.co.nz/robots.txt

Only Home, About, Our Story and Contact appear in the sitemap. Login, registration, password-reset and member responses receive `noindex`; authentication continues to protect member data. Local and alternate hostnames are also marked `noindex`.

1. After deployment, open both endpoints and confirm they load.
2. Open [Google Search Console](https://search.google.com/search-console), select the lodge property, or add and verify it if needed.
3. Under Sitemaps, submit `https://lodgematariki476.co.nz/sitemap.xml`.
4. Use URL inspection for the homepage, About, Our Story and Contact, and request indexing where appropriate.
5. Check the homepage with [Google's Rich Results Test](https://search.google.com/test/rich-results), then monitor Search Console for indexing issues.

Google decides whether and where to show a page. These improvements cannot guarantee first place or immediate indexing. No reviews, ratings or unverified claims were added.

## Verification and deployment

Run the repository's Security and end-to-end tests workflow. It covers password reset with PostgreSQL, mocked SMTP delivery, missing-schema and timeout failures, 499/500/501-character contact boundaries, browser counter behaviour, and public/private SEO metadata. Mocked SMTP and suppressed CI email do not establish real inbox delivery.

Before merging/deploying, confirm member uploads are backed up and mounted on persistent storage. The earlier `/app/instance` recovery paths alone do not guarantee persistence in Azure. This change does not merge or deploy itself.

Sources: [Bootstrap text utilities](https://getbootstrap.com/docs/5.3/utilities/text/), [Python SMTP](https://docs.python.org/3/library/smtplib.html), [Google SEO guide](https://developers.google.com/search/docs/fundamentals/seo-starter-guide), [Google noindex guidance](https://developers.google.com/search/docs/crawling-indexing/block-indexing).
