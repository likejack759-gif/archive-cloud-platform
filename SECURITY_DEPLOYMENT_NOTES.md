# Security rollout notes

This branch adds fail-closed ClamAV scanning and archive-entry checks to uploads. The application requires a reachable ClamAV daemon configured with `CLAMAV_HOST` and `CLAMAV_PORT`; if scanning is unavailable, new uploads are rejected rather than treated as clean.

The database migration adds `resources.scan_status` and `resources.scan_result` using `ADD COLUMN IF NOT EXISTS`, preserving existing records. Existing resources are marked `pending` for scan status and must be rescanned by an administrator before approval. The admin page includes a rescan action. A resource can be approved or downloaded only when its scan status is `clean`.

Do not deploy this branch until the application container can resolve and reach the ClamAV service, the S3-compatible endpoint and PostgreSQL environment variables are configured, and tests have passed. Keep the existing `.env` and object-storage credentials private. Never replace the production database or storage volume during rollout.
