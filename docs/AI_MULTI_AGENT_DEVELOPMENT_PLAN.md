# Multi-Agent Development Workflow

## Status

Design and platform-selection plan only. No agent platform has been installed or connected yet. No production server, database, object-storage bucket, or user file has been changed.

## Objective

Use multiple independent AI coding/review agents to recover, improve, test, and maintain CLOUD FILE CENTER while preventing unreviewed changes from reaching production. Borrow safe multi-agent coordination ideas; do not deploy autonomous offensive penetration-testing capabilities.

## Current repository baseline

- Repository: `likejack759-gif/archive-cloud-platform`
- Working branch: `recovery/restore-features-20261030`
- Baseline HEAD at plan creation: `e70f244b21b4c6fe216b6480c50b1c01b3c3990e`
- Production deployment remains frozen.
- Existing validation workflow runs Python compilation, Jinja2 parsing, pytest, and Docker Compose configuration checks.
- Latest recorded passing test baseline is 35 passed, 3 skipped, 2 warnings at commit `b62c459d4d4442b4980e88cb271814aa89a3cb57`. This is not a production integration test.

## Platform decision for Android-first, near-zero-budget operation

### Primary candidate: Paseo

Paseo is currently the best fit to evaluate first because it provides native Android and desktop clients, parallel coding agents in separate Git worktrees, cross-agent delegation, diffs, Git operations, and self-hosted execution.

- Project: https://github.com/getpaseo/paseo
- Android listing: https://play.google.com/store/apps/details?id=sh.paseo
- Desktop downloads: https://paseo.sh/download
- The Android app is a control client; the agent daemon and coding CLIs run on a separate host.
- Paseo is open source (Apache-2.0) and does not require a forced account login. Agent/model usage may still require provider credentials or subscriptions.
- A phone can pair with the host through the supported encrypted relay or a private network connection.
- Do not assume local Ollama compatibility until a supported provider/custom-provider configuration is tested.

### Secondary candidate: Happier

Happier is another open-source Android control app and orchestrator, with Windows support, multi-agent sessions, cross-agent delegation, and Git/worktree review.

- Project: https://github.com/happier-dev/happier
- Android app and onboarding: https://docs.happier.dev/getting-started/get-the-apps
- It is free/open source, but likewise requires a machine running the agent CLI/daemon and the underlying agent credentials or subscriptions.

### Not selected as the first Android path: OpenHands Mobile

OpenHands Mobile is an early MVP that currently connects to an already-running OpenHands agent-server using a host URL and session API key. Its own README says QR pairing, hosted relay, and several management surfaces are not yet built. It is therefore less convenient for the requested phone-first setup.

- Project: https://github.com/OpenHands/openhands-mobile

### Cost reality

The orchestration software and Android clients can be free. That does not mean every AI model is free. To keep ongoing cost near zero, first test the user's existing Windows laptop and local Ollama/Qwen endpoint through a supported coding-agent adapter. Local inference has no per-token API bill, but is constrained by laptop RAM/CPU/GPU and model coding quality. Do not purchase API credits or a hosted VM without explicit approval.

## Proposed operating layout

- Android phone: install Paseo client; view agent sessions, approve actions, inspect diffs, and steer tasks.
- Windows 11 laptop: run Paseo desktop/daemon and isolated project workspaces; keep the laptop awake and online while jobs run.
- Local model: evaluate existing Ollama/Qwen as the first no-API-cost model path; verify tool-calling, context size, code editing, and concurrency before relying on it.
- GitHub: all work remains on `recovery/restore-features-20261030` or separate task branches and pull requests.
- Production VPS: never host the agent daemon and never expose production credentials or data to agents.

If the laptop is off or disconnected, laptop-hosted agents stop being reachable. Continuous work while the laptop is off would require a separate development host; the production VPS is explicitly excluded.

## Agent roles

- Coordinator / architect: decomposes approved tasks, defines acceptance criteria, tracks dependencies, and integrates reports. It does not deploy.
- Frontend agent: templates, styling, responsive behavior, accessibility, and browser checks.
- Backend agent: FastAPI routes, validation, authentication, database and object-storage integration.
- Security reviewer: defensive code review, authorization/CSRF/session/upload/download checks, dependency review, and scoped tests against owned isolated environments only.
- Test / QA agent: regression tests, integration tests, failure-mode tests, and evidence collection.
- Independent reviewer: reviews diffs and test evidence produced by other agents; cannot approve its own changes.

Start with only two agents (coder + independent reviewer). Add roles only after the two-agent workflow is stable. Never let agents share one writable working tree; use isolated worktrees/branches.

## GitHub delivery path

1. Human approves a task and its scope.
2. Coordinator creates a task brief with files allowed to change, prohibited files, and acceptance criteria.
3. A coding agent works in an isolated worktree/branch.
4. A different agent reviews the diff and identifies risks.
5. GitHub Actions runs required checks.
6. QA runs isolated integration tests using disposable PostgreSQL and S3-compatible test resources.
7. Human reviews the PR and decides whether to merge.
8. A separate release checklist and explicit human approval are required before any production deployment.

No agent may push directly to `main`, merge its own PR, modify production secrets, or deploy to the VPS.

## 502 prevention and release safety gates

A passing unit-test workflow is necessary but insufficient. Before any future release, require:

- Python syntax and dependency checks.
- Jinja2 template compilation and route/template consistency checks.
- Full regression tests for registration, login, invite codes, upload, review, deletion, listing, and download.
- Isolated PostgreSQL integration tests including migrations and concurrency-sensitive behavior.
- Isolated S3-compatible storage tests for upload, metadata, download, and cleanup.
- Container image build and Compose validation.
- Container startup and readiness checks with bounded startup time.
- HTTP smoke tests against the app directly and through a staging reverse proxy.
- Nginx upstream connectivity and health checks in staging.
- Failure tests for unavailable database, unavailable object storage, app restart, and invalid configuration.
- A release artifact/image pinned by immutable digest.
- A documented rollback target and a tested rollback procedure.

If any required gate fails, stop the release. Do not replace the currently running version. These gates reduce release-induced 502 risk but cannot guarantee that outages will never occur.

## Production isolation rules

- Never use the production VPS as an agent execution host.
- Never give agents production SSH credentials, root access, or unrestricted shell access.
- Never mount production `.env`, database volumes, SeaweedFS data, or user uploads into an agent sandbox.
- Never run destructive cleanup, schema reset, bucket deletion, or volume deletion as an automated recovery step.
- Do not expose ClamAV or other internal services publicly. Scanner status must remain unavailable until a private endpoint is configured and verified.
- Only test systems and domains explicitly owned or authorized by the user.
- Human approval is mandatory for secrets, permissions, merges, and deployment.

## Implementation sequence

1. Install the official Paseo Android app from Google Play and verify publisher/project links.
2. On the Windows laptop, install the official Paseo desktop app and verify the daemon starts.
3. Pair Android with the laptop using Paseo's supported pairing flow. Do not expose a raw daemon port publicly.
4. Clone the repository into a dedicated development folder, check out the recovery branch, and create isolated worktrees. Do not use production directories.
5. Configure one coding agent and test local Ollama/Qwen integration. If local model tool use or quality is insufficient, stop and compare genuinely free alternatives before considering paid APIs.
6. Run a harmless two-agent proof of concept on documentation-only changes: one agent edits a disposable branch, another reviews it.
7. Verify GitHub Actions results and manual approval gates.
8. Only then connect the agents to actual website tasks.

## ARTEX boundary

ARTEX is an autonomous penetration-testing system. Do not deploy its offensive execution capabilities as a website-development agent. Borrow only safe coordination concepts such as task decomposition, shared progress, evidence trails, approval gates, and independent review.
