# Security policy

## Reporting a vulnerability

Do not open a public issue containing credentials, personal information, exploit details, or member documents. Contact the repository owner privately with:

- the affected route or component;
- reproduction steps;
- impact and any evidence;
- a safe remediation suggestion, if available.

Please do not access, modify, or retain real member data while testing.

## Supported version

Only the latest deployed commit on `main` is supported. Security changes must pass the repository's **Security and end-to-end tests** workflow before deployment.

## Operational requirements

- Production secrets belong in Azure App Settings or a secret manager, never Git.
- `SECRET_KEY` must contain at least 32 unpredictable characters.
- Production must use HTTPS, `APP_ENV=production`, `SESSION_COOKIE_SECURE=1`, and an explicit `TRUSTED_HOSTS` list.
- Protected documents must use a private persistent storage mount at `FILE_UPLOAD_FOLDER`; they must never be placed under `app/static`.
- Use a shared rate-limit backend through `RATELIMIT_STORAGE_URI` when running multiple workers or instances.
- Rotate credentials immediately if they are ever committed, logged, or shared.

