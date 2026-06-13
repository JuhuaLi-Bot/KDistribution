# Text Gist Service

A small dependency-free Node.js service for hosting editable text snippets. Users can register, sign in, create gists, edit their own gists, and share stable raw text links.

## Features

- Local username/password accounts.
- Passwords hashed with `crypto.scrypt`.
- File-backed persistence under `data/`.
- Random URL-safe gist IDs.
- Public read-only gist pages.
- Stable plain text links at `/raw/:id`.
- Owner-only edit and delete actions.
- Startup-created administrator account with a random one-time password.
- User center for password changes.
- Admin center for user management and free-registration controls.
- Basic CSRF protection for authenticated write forms.

## Quick Start

```sh
npm run smoke
npm start
```

The default URL is:

```text
http://127.0.0.1:3456
```

For production setup, reverse proxy, systemd, Docker, backups, and upgrade steps, see [DEPLOYMENT.md](DEPLOYMENT.md).

## Configuration

- `HOST` defaults to `127.0.0.1`.
- `PORT` defaults to `3456`.
- `DATA_DIR` defaults to `./data`.
- `PUBLIC_BASE_URL` controls the absolute raw URL shown in the UI.
- `MAX_TEXT_BYTES` defaults to `1048576`.
- `COOKIE_SECURE=true` should be used when serving only over HTTPS.
- `ADMIN_USERNAME` defaults to `admin`.

Copy `.env.example` when you want a concrete starting point for production environment variables.

On first startup, if no administrator exists, the service creates `ADMIN_USERNAME` with a random password. The credentials are printed to stdout and saved once at `DATA_DIR/admin-credentials.txt`.

## Test

```sh
npm run smoke
```

The smoke test creates a temporary data directory, registers a user, creates a gist, checks the raw link, edits the gist, and checks the raw link again.

## HTTP Endpoints

- `GET /` dashboard, sign-in, and registration page.
- `GET /account` user center.
- `POST /account/password` change the signed-in user's password.
- `GET /admin` admin center.
- `POST /admin/settings` open or close free registration.
- `POST /admin/users` create a user as an administrator.
- `POST /admin/users/:id/action` enable, disable, promote, demote, or reset a user password.
- `POST /register` create an account.
- `POST /login` sign in.
- `POST /logout` sign out.
- `POST /gists` create a gist.
- `GET /gists/:id` public view, or editable owner view when signed in.
- `POST /gists/:id` update an owned gist.
- `POST /gists/:id/delete` delete an owned gist.
- `GET /raw/:id` persistent `text/plain` view of the current gist content.
- `GET /healthz` health check.

## Data Layout

The service stores all mutable state in `DATA_DIR`:

- `users.json` contains account records and password hashes.
- `sessions.json` contains active login sessions.
- `gists.json` contains gist metadata.
- `settings.json` contains site-level settings such as whether free registration is open.
- `admin-credentials.txt` contains the first generated admin password if the admin was auto-created.
- `gists/*.txt` contains the plain text body for each gist.