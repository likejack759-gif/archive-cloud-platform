# Recovery development log

## Guardrails

- All recovery work stays on `recovery/restore-features-20261030`.
- Do not commit recovery changes directly to `main`.
- Do not deploy from this branch to the VPS.
- Do not run destructive database, bucket, volume, or Docker cleanup commands as part of code recovery.
- Keep user data and object-storage data outside source-code changes.
- Any production deployment requires a separate review and explicit user approval.

## Recovered baseline

The branch was created from `feature/integrated-resource-safety`, commit:

`672adfb8b09bfa152bbb8b755e83c9d52189147a`

The recovered tree includes the FastAPI application, Jinja2 templates, PostgreSQL schema initialization, S3-compatible object storage integration, resource quota helper, security checks, and regression tests.

## Changes made during this recovery pass

1. Updated `app/templates/base.html` with a shared dark celestial glassmorphism theme, metallic gold/ice-blue accents, responsive navigation, form/table states, and reduced-motion support. Existing route links, CSRF fields, and Jinja blocks were preserved.
2. Updated `app/templates/index.html` hero copy and visual treatment to use the celestial-dragon archive identity. Existing search/filter query names and resource rendering logic were preserved.
3. Updated `docker-compose.yml` to require PostgreSQL and S3-compatible storage settings instead of silently starting an app container without the dependencies required by `app/main.py`.
4. Expanded `.env.example` with the actual app configuration contract, including database, S3, rate-limit, trusted-proxy, and optional ClamAV settings. It contains placeholders only.
5. Updated GitHub Actions triggers so pushes to `recovery/**` run validation and security checks. Compose validation supplies non-production CI placeholders.
6. Replaced the obsolete SQLite/local-file deployment README with documentation for the PostgreSQL + S3-compatible architecture and its known limitations.

## Important configuration facts

- `DATABASE_URL` is mandatory; the application raises an error at startup if it is absent.
- S3 endpoint, access key, secret key, region, and bucket are mandatory when object-storage operations are used.
- The current Compose file defines the application container only. PostgreSQL and SeaweedFS/S3 must be provided separately and be reachable from the app container.
- Empty or unavailable ClamAV configuration yields `unavailable`, not `clean`. Do not claim the scanner is operational until an actual scanner endpoint is configured and tested.
- ZIP/APK content listing and bounded text preview are implemented; 7Z/RAR content browsing is not yet implemented.
- This pass has not deployed anything and has not changed the production VPS.

## Validation still required

- Wait for GitHub Actions on this branch and inspect failures.
- Verify all Jinja templates parse and all existing tests pass.
- Run integration tests against isolated PostgreSQL and an isolated S3-compatible bucket.
- Confirm the target VPS's actual SeaweedFS S3 endpoint, bucket, access-key pair, database URL, and network topology before preparing a deployment configuration.
- Review all recovered feature routes and templates against the original product requirements.
