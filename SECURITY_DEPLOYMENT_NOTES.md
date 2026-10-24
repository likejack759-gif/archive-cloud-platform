# Security and server deployment notes

## Included controls

- ClamAV INSTREAM malware scan; upload is rejected unless scanner returns `clean`.
- ZIP/APK entry checks for traversal paths, symbolic links, encrypted entries, entry count, and expanded-size limits.
- PostgreSQL additive migrations for scan state and SHA-256; existing tables are not dropped or rebuilt.
- Approval and download are denied unless scan state is `clean`.
- Admin scan queue and rescan action for legacy objects.
- CSRF validation on state-changing HTML forms.
- Persistent login failure throttling by username hash and client-IP hash.
- Configurable per-user and platform storage quotas; final quota check and insert use a PostgreSQL advisory transaction lock.
- SHA-256 digest recorded for each newly uploaded archive.

## Compose prerequisites

1. Copy `.env.example` to `.env`; replace every placeholder with unique secrets. Do not commit `.env`.
2. Copy `seaweedfs-s3.json.example` to `seaweedfs-s3.json`. Replace the sample access key and secret with the exact same values as `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` in `.env`. Keep the real JSON file private and do not commit it.
3. Confirm the selected SeaweedFS image version supports the configured `server -s3 -s3.config=...` command and S3 identity schema before deploying. The S3 API is exposed only to the Compose network; the application creates the configured bucket at startup.
4. The Compose file mounts `clamd.conf` to raise ClamAV stream/file limits above the configured 2048 MiB upload limit. Verify the selected `clamav/clamav:1.4` image honors this config path and can load its virus database. Scanner startup/availability has not been end-to-end verified here.
5. Keep the app bound to `127.0.0.1:8000` behind Nginx by default. Set `TRUSTED_PROXY_IPS` only to the exact trusted reverse-proxy peer address(es); never trust arbitrary forwarded headers. Set `SESSION_HTTPS_ONLY=true` only when HTTPS is configured.
6. Ensure the Nginx client-body limit and timeout are compatible with the selected maximum upload size; otherwise Nginx can reject large files before FastAPI receives them.

## Data migration and legacy resources

The application adds columns with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`; it does not drop existing tables. Legacy resources get `scan_status=pending` and are intentionally not downloadable until an administrator rescans them successfully. This is a security lock, not a data deletion. Before rollout, take a database backup and confirm all object keys still point to the existing storage.

The new `sha256` column is populated for new uploads only. Existing resources have an empty digest until a separately verified backfill is implemented. Do not treat an empty legacy digest as integrity verification.

## Validation status

CI checks Python compilation, Jinja template parsing, Compose syntax, and focused upload-security unit tests. These checks do not prove that PostgreSQL, SeaweedFS, ClamAV, Nginx, and large-file uploads work together in a live environment. Run a staging deployment with test data and an EICAR test file before production rollout.

## Rollout restrictions

This PR is a draft and is not deployed or merged. Do not point production at this branch until all CI checks pass and the service integration is exercised in staging. Never replace the production database or storage volume during rollout; keep credentials and backups private.
