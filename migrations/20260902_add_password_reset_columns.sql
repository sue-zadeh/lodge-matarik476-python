-- Safe to run more than once on the existing Azure PostgreSQL database.
BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_reset_token VARCHAR(255);

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_reset_token_expiry TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS users_password_reset_token_unique
    ON users(password_reset_token)
    WHERE password_reset_token IS NOT NULL;

COMMIT;
