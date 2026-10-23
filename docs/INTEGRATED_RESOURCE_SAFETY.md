# Integrated resource safety features

This branch adds the following preview-only features. It is not deployed to the production VPS.

## Upload and storage flow

1. Upload bytes are streamed to a temporary file and checked against the upload limit and file signature.
2. The existing ClamAV `clamd INSTREAM` interface scans the original bytes. A positive detection rejects the upload. A missing/unreachable scanner records `unavailable`; it is not treated as clean and cannot be approved.
3. A SHA-256 digest is recorded for the original file.
4. Zstandard level 3 compression is attempted on disk. The compressed representation is stored only if it saves at least 1%; otherwise the original bytes are stored. A free-space margin of 256 MiB is required before attempting secondary compression.
5. Downloads stream the stored object and transparently restore Zstandard-wrapped files. The user receives the original filename and original bytes. The archive itself is not extracted on the server.
6. Admin ZIP/APK preview restores only the outer Zstandard wrapper to a temporary file; it does not extract archive members. It checks free disk space first and cleans up temporary files.

Compression is lossless, but many ZIP/7Z/RAR/APK files will not shrink further. Those are stored unchanged. Temporary compression needs free disk space; concurrent uploads and large files should still be monitored.

## Resource deletion

- Users may delete only resources they own; administrators may delete any resource.
- The action requires a CSRF token and a confirmation prompt.
- The row is marked `deleting` before storage deletion. If an object-store delete fails, the row remains for investigation/retry rather than claiming success.
- Object storage backup/version retention is independent; deleting the live resource does not promise immediate erasure from backup history.

## IP ban / unban and anti-crawler throttling

- Administrators can ban an exact IPv4 or IPv6 address for 10 minutes, 1 hour, 24 hours, or permanently.
- The current admin client IP cannot be banned through the UI.
- Expired bans stop applying automatically; administrators can revoke active bans manually.
- Every successful ban, unban, or resource deletion is recorded in `security_audit_log`.
- IP bans are exact-address only, not CIDR ranges. Shared/public IPs can represent many legitimate visitors, so use short durations unless reviewed.
- A bounded in-process request limiter defaults to 120 requests per IP per 60 seconds and returns HTTP 429 with `Retry-After`; `/health` is exempt. Tune `REQUEST_RATE_LIMIT` and `REQUEST_RATE_WINDOW_SECONDS` carefully. This limiter is per app process, so Nginx-level limiting should also be used for multi-worker/multi-instance deployments.

### Reverse-proxy requirement

The app must receive the real client address from a trusted reverse proxy. `X-Real-IP` is only trusted when the direct peer IP is listed in `TRUSTED_PROXY_IPS`. Determine the address used by the reverse proxy to connect to the app container, then configure it in the deployment environment, for example:

```env
TRUSTED_PROXY_IPS=127.0.0.1,::1,172.17.0.1
```

The example bridge address is not universal; verify the actual Docker network gateway before deployment. The preview Compose file binds port 8000 to localhost so it is not intended to be exposed directly to the Internet. Keep the reverse proxy and firewall configuration aligned.

## Scanner configuration

The ClamAV interface is already present in the app. It still requires a reachable, private `clamd` service:

```env
CLAMAV_HOST=<private scanner hostname or IP>
CLAMAV_PORT=3310
CLAMAV_TIMEOUT_SECONDS=30
```

Do not expose TCP 3310 to the public Internet. Scanner timeouts/unavailability must remain fail-closed for publication. A successful connection alone is not proof of malware detection; use the harmless EICAR test file in an isolated staging environment.

## Validation checklist

- Run `pytest -q`.
- Verify a compressible test file round-trips byte-for-byte and a non-compressible file remains raw.
- In staging, verify clean scan -> pending review -> admin approval -> download with the exact original SHA-256.
- Verify infected upload rejection and unavailable-scanner fail-closed behavior.
- Verify owner can delete own resource, cannot delete another user's resource, admin can delete any resource, and failed object deletion leaves a retryable row.
- Verify ban expiry, manual unban, admin self-ban prevention, and real client IP behind the actual reverse proxy.
- Check disk headroom and memory under the maximum configured upload size before production rollout.

Do not merge this branch or apply it to the production VPS until these checks and a backup restore test pass.
