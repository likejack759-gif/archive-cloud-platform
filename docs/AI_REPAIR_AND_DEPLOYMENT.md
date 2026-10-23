# AI repair agent and production deployment

## Workflow
1. The website saves each feedback report to PostgreSQL first.
2. If GITHUB_ISSUES_TOKEN is configured on the VPS, the server creates a GitHub issue using the report prefix. A GitHub outage does not discard the saved report.
3. The AI Bug Repair Agent runs in an ephemeral GitHub Actions runner, treats issue text as untrusted data, and may modify only app/ and tests/ files.
4. The agent runs compileall, pytest, Jinja template parsing, and Docker Compose configuration validation. If all checks pass, it pushes a dedicated branch and opens a PR against main. It never writes directly to main.
5. A push to main triggers the Validate and Deploy Production workflow. It re-runs checks, then backs up application source and PostgreSQL data on the VPS, updates only the application service, checks /health, and attempts rollback if the build or health check fails.

## Required secrets
Configure these as repository Actions secrets before the workflow can deploy:
- OPENAI_API_KEY: OpenAI API key with API billing enabled. ChatGPT subscription does not include API usage.
- PRODUCTION_HOST: VPS host/IP.
- PRODUCTION_USER: SSH user for deployment; a restricted deployment account is preferred over root.
- PRODUCTION_SSH_KEY: SSH private key corresponding to the VPS authorized key.
- PRODUCTION_KNOWN_HOSTS: previously verified SSH host-key line. Do not disable host-key verification.

Configure the following in the VPS .env file; never commit or post token values:
- GITHUB_ISSUES_TOKEN: fine-grained token limited to this repository with Issues read/write.
- GITHUB_ISSUES_REPOSITORY=likejack759-gif/archive-cloud-platform

After changing the VPS .env, restart only the application service to load the new environment.

## Safety constraints
- Public report text is untrusted data. Never execute commands copied from a report.
- AI changes are limited to app/ and tests/. Workflow, dependency, secret, deployment, database and storage changes are prohibited.
- The AI does not merge its own PR. Production deploy is automatic after a change is merged into main and validation succeeds; review/merge remains a deliberate gate against public reports directly deploying arbitrary code.
- Production deployment uses the existing VPS docker-compose.yml and .env; it must preserve PostgreSQL and SeaweedFS volumes, /data, Nginx and TLS settings.
- Backups need sufficient free disk space. A database dump is a backup artifact, not a proof of successful restore; verify restore procedures separately.
- OpenAI API calls incur separate charges. Set account spending limits and monitor public report abuse.

## Initial enablement checklist
1. Configure the required GitHub Actions secrets and the two VPS .env settings.
2. Verify the SSH host key independently before saving PRODUCTION_KNOWN_HOSTS.
3. Run the validation workflow on the feature branch and fix all failures.
4. Confirm the production workflow's remote backup and rollback commands against the actual VPS service names before merging this workflow into main.
5. Keep the AI agent PR unmerged until the CI results and deployment prerequisites are verified.