# File Sharing API

A REST API for uploading, managing, and sharing files, built with Rust and Axum.

## Deployment

**Live at [files.tanciaku.com](https://files.tanciaku.com)**

```bash
# Health check
curl https://files.tanciaku.com/health
```

The API is self-hosted on a Debian VPS, manually configured from scratch.

### Stack

| Layer | Technology |
|---|---|
| Language | Rust (Axum) |
| Database | PostgreSQL (sqlx, auto-migrations on startup) |
| Web server | Nginx (reverse proxy, rate limiting) |
| TLS | Let's Encrypt — A+ rated |
| OS | Debian 13 (VPS) |
| CI/CD | GitHub Actions — builds release binary, runs migrations, deploys on push to `main` |

### Security highlights

- SSH: key-only authentication, non-standard port, root login disabled
- Firewall: UFW — only ports 80, 443, and SSH exposed
- Intrusion prevention: Fail2ban watching SSH and Nginx (auth brute force, 4xx scanning, rate limit violations)
- Rate limiting: Nginx `limit_req_zone` on upload, download, and auth endpoints
- Security headers: A+ rated (HSTS, CSP, X-Frame-Options, etc.)
- Database: PostgreSQL bound to localhost only, least-privilege app user
- App process: runs as a dedicated system user with no login shell
- Secrets: managed via a root-only environment file, not in the service unit

---

## Features

- Upload files with server-side validation (type and size)
- Download files by ID
- Delete your own files
- List your uploaded files with pagination
- Get file metadata including download count
- Generate shareable, time-limited download links
- PostgreSQL persistence via sqlx
- JWT-based authentication (HS256, 24-hour tokens)
- Argon2 password hashing

## Quick Start

1. Create a `.env` file with your database connection and secret:

```bash
echo "DATABASE_URL=postgres://user:password@localhost/file_sharing" > .env
echo "JWT_SECRET=your-secret-key" >> .env
# For running tests, also set:
echo "TEST_DATABASE_URL=postgres://user:password@localhost/file_sharing_test" >> .env
```

2. Run database migrations:

```bash
cargo sqlx migrate run
```

3. Start the server:

```bash
cargo run
```

The server will start on `http://localhost:3000`. You can override the port with a `PORT` environment variable.

## API Endpoints

### Auth

- `POST /auth/login` — Log in and receive a JWT

### Files

- `GET /health` — Health check
- `POST /upload` — Upload a file *(requires JWT)*
- `GET /files` — List your uploaded files with pagination *(requires JWT)*
- `GET /files/{id}` — Download a file by ID
- `DELETE /files/{id}` — Delete a file *(requires JWT, owner only)*
- `GET /files/{id}/meta` — Get file metadata *(requires JWT, owner only)*
- `POST /files/{id}/share` — Generate a shareable download link *(requires JWT, owner only)*
- `GET /files/shared/{token}` — Download a file via a share token *(no auth required)*

### Example Requests

**Log in:**
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "hunter2"}'
```

Returns `200 OK` with a JWT valid for 24 hours, or `401 Unauthorized` on bad credentials.

```json
{
  "token": "eyJ0eXAiOi..."
}
```

**Upload a file:**
```bash
curl -X POST http://localhost:3000/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@/path/to/document.pdf"
```

Returns `200 OK` with the new file's ID, or `415 Unsupported Media Type` if the file type is not allowed, or `413 Payload Too Large` if the file exceeds 10 MB.

```
File ID: 3db451d1-54c8-4c38-8249-9e2e4bf986a9
```

**Download a file:**
```bash
curl -O -J http://localhost:3000/files/3db451d1-54c8-4c38-8249-9e2e4bf986a9
```

Returns `200 OK` with the file as an attachment, or `404 Not Found` if the ID doesn't exist.

**List your files:**
```bash
curl http://localhost:3000/files \
  -H "Authorization: Bearer <token>"
```

**Paginate results:**
```bash
curl "http://localhost:3000/files?page=2&per_page=10" \
  -H "Authorization: Bearer <token>"
```

> `page` defaults to `1` and `per_page` defaults to `20` (max `100`).

```json
{
  "files": [
    {
      "id": "3db451d1-54c8-4c38-8249-9e2e4bf986a9",
      "original_name": "document.pdf",
      "size_bytes": 204800,
      "uploaded_at": "2026-04-07T12:00:00+00:00",
      "download_count": 3
    }
  ],
  "page": 1,
  "per_page": 20,
  "total": 1
}
```

**Get file metadata:**
```bash
curl http://localhost:3000/files/3db451d1-54c8-4c38-8249-9e2e4bf986a9/meta \
  -H "Authorization: Bearer <token>"
```

Returns `200 OK` with the file's metadata, or `404 Not Found` if the file doesn't belong to you.

```json
{
  "id": "3db451d1-54c8-4c38-8249-9e2e4bf986a9",
  "original_name": "document.pdf",
  "size_bytes": 204800,
  "uploaded_at": "2026-04-07T12:00:00+00:00",
  "download_count": 3
}
```

**Create a share token:**
```bash
curl -X POST http://localhost:3000/files/3db451d1-54c8-4c38-8249-9e2e4bf986a9/share \
  -H "Authorization: Bearer <token>"
```

Returns `200 OK` with a share token and a ready-to-use download URL, or `403 Forbidden` if the file doesn't belong to you.

```json
{
  "token": "a1b2c3d4-...",
  "expires_at": "2026-04-08T12:00:00+00:00",
  "download_url": "/files/shared/a1b2c3d4-..."
}
```

**Download via share link:**
```bash
curl -O -J http://localhost:3000/files/shared/a1b2c3d4-...
```

No authentication required. Returns `410 Gone` if the token has expired.

**Delete a file:**
```bash
curl -X DELETE http://localhost:3000/files/3db451d1-54c8-4c38-8249-9e2e4bf986a9 \
  -H "Authorization: Bearer <token>"
```

Returns `204 No Content` on success, `403 Forbidden` if the file doesn't belong to you, or `404 Not Found` if the ID doesn't exist.

## File Validation

The following rules are enforced on every upload:

- **Maximum size**: 10 MB
- **Allowed extensions**: `png`, `jpg`, `jpeg`, `gif`, `webp`, `pdf`, `txt`
- **Allowed MIME types**: `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `application/pdf`, `text/plain`

Both the file extension and the declared `Content-Type` must be in the allowed lists. Violations return `415 Unsupported Media Type`.

## Data Model

### User

```json
{
  "id": 1,
  "username": "alice",
  "created_at": "2026-04-07T12:00:00+00:00"
}
```

Passwords are hashed with Argon2 and never returned in responses.

### File

```json
{
  "id": "3db451d1-54c8-4c38-8249-9e2e4bf986a9",
  "original_name": "document.pdf",
  "size_bytes": 204800,
  "uploaded_at": "2026-04-07T12:00:00+00:00",
  "download_count": 3
}
```

`download_count` is incremented on every direct download and every successful shared download.

### Share Token

```json
{
  "token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "expires_at": "2026-04-08T12:00:00+00:00",
  "download_url": "/files/shared/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

Share tokens expire after 24 hours. Accessing a shared link after expiry returns `410 Gone`. Deleting the parent file also deletes all of its share tokens (`ON DELETE CASCADE`).

## Testing

The project includes an integration test suite covering all endpoints against a real PostgreSQL database.

Test coverage includes:
- Upload validation — rejects disallowed extensions, disallowed MIME types, and files exceeding 10 MB
- Login — returns a JWT on valid credentials, `401` on wrong password
- Upload and download — end-to-end round-trip verifying file content is preserved
- List files — returns only the authenticated user's own files, correct totals, and correct pagination across multiple pages
- List files requires authentication — returns `401` without a token
- Delete — owner deletes successfully (`204`), non-owner receives `403 Forbidden`
- Create share token — returns a token UUID and a valid download URL
- Create share token forbidden — non-owner receives `403 Forbidden`
- Download via share link — unauthenticated download returns the correct file content
- Download via expired share link — returns `410 Gone`
- File metadata — returns correct `original_name`, `size_bytes`, and `download_count`
- File metadata requires auth — returns `401` without a token
- File metadata scoped to owner — non-owner receives `404 Not Found`
- Download increments `download_count` (direct download)
- Download increments `download_count` (shared download)

To run the tests:

```bash
cargo test -- --test-threads=1
```

Ensure `TEST_DATABASE_URL` is set in your `.env`. Each test run truncates all tables with `RESTART IDENTITY CASCADE` to start from a clean state.

## Notes

- Files are stored on disk under `./uploads/`, named by their UUID.
- Data is persisted in a PostgreSQL database specified by `DATABASE_URL`.
- A `JWT_SECRET` environment variable must be set; it is used to sign and verify all tokens.
- Tokens are signed with HS256 and expire after 24 hours.
- Passwords are hashed with Argon2 (default parameters) before storage.
- There is no registration endpoint by design. User accounts are created with the included `create_user` binary:
  ```bash
  cargo run --bin create_user <username> <password>
  ```
- Share tokens are deleted automatically when the associated file is deleted.

## License

MIT
