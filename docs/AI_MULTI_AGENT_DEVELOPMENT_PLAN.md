# Multi-Agent Development Workflow

## Status

Design proposal only. No agent platform has been installed or connected yet. No production server, database, object-storage bucket, or user file has been changed.

## Objective

Use multiple independent AI coding/review agents to recover, improve, test, and maintain CLOUD FILE CENTER while preventing unreviewed changes from reaching production. This is a software-delivery workflow inspired by the coordination and evidence-tracking ideas of multi-agent systems; it is not an autonomous penetration-testing deployment.

## Current repository baseline

- Repository: `likejack759-gif/archive-cloud-platform`
- Working branch: `recovery/restore-features-20261030`
- Baseline HEAD at plan creation: `e70f244b21b4c6fe216b6480c50b1c01b3c3990e`
- Production deployment remains frozen.
- Existing validation workflow runs Python compilation, Jinja2 parsing, pytest, and Docker Compose configuration checks.
- Latest recorded passing test baseline is 35 passed, 3 skipped, 2 warnings at commit `b62c459d4d4442b4980e88cb271814aa89a3cb57`. This is not a production integration test.

## Proposed architecture

### 1. Human-controlled orchestration console

Evaluate OpenHands Agent Canvas as the operator console because its documented workflow covers issue/task intake, agent execution, validation, PR creation/review, and multiple agent backends. Run it on a separate development machine or isolated development host, never inside the production application stack.

Official references:
- https://github.com/OpenHands/OpenHands
- https://docs.openhands.dev/openhands/usage/run-openhands/github-action

Do not assume Agent Canvas alone supplies a complete autonomous multi-agent team. The first implementation should use separate, explicitly assigned agent sessions and a human-controlled coordinator. Consider a dedicated graph orchestrator (for example LangGraph) only if the initial workflow demonstrates a concrete need.

### 2. Agent roles

- Coordinator / architect: decomposes approved tasks, defines acceptance criteria, tracks dependencies, and integrates reports. It does not directly deploy.
- Frontend agent: templates, styling, responsive behavior, accessibility, and browser-level checks.
- Backend agent: FastAPI routes, validation, authentication, database and object-storage integration.
- Security reviewer: defensive code review, authorization/CSRF/session/upload/download checks, dependency review, and scoped tests against owned isolated environments only.
- Test / QA agent: regression tests, integration tests, failure-mode tests, and evidence collection.
- Independent reviewer: reviews diffs and test evidence produced by other agents; cannot approve its own changes.

Agents must not share one writable working tree. Give each task an isolated workspace and branch or worktree. Merge through reviewed pull requests only.

### 3. GitHub delivery path

1. Human approves a task and its scope.
2. Coordinator creates a task brief with files allowed to change, files prohibited from changing, and acceptance criteria.
3. A coding agent works in an isolated branch/worktree.
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

If any required gate fails, stop the release. Do not replace the currently running version.

## Production isolation rules

- Never use the production VPS as an agent execution host.
- Never give agents production SSH credentials, root access, or unrestricted shell access.
- Never mount production `.env`, database volumes, SeaweedFS data, or user uploads into an agent sandbox.
- Never run destructive cleanup, schema reset, bucket deletion, or volume deletion as an automated recovery step.
- Do not expose ClamAV or other internal services publicly. Scanner status must remain unavailable until a private endpoint is configured and verified.
- Only test systems and domains explicitly owned or authorized by the user.
- Human approval is mandatory for secrets, permissions, merges, and deployment.

## Platform selection notes

OpenHands is the initial candidate for a development-agent console, not a final installation decision. The current production VPS has limited resources and must remain isolated; do not install the agent platform there. The user's Windows development laptop or a separate disposable development host is a safer place to evaluate it. Before installation, verify current OS/Docker prerequisites, model/API compatibility, concurrency limits, costs, and sandbox isolation.

ARTEX itself is an autonomous penetration-testing system. Do not deploy its offensive execution capabilities as a website-development agent. Borrow only safe coordination concepts such as task decomposition, shared progress, evidence trails, approval gates, and independent review.

## Next steps

1. Confirm the intended development host (Windows laptop or a separate non-production host).
2. Confirm which model endpoints are available and acceptable for use (hosted APIs and/or the user's local Ollama endpoint).
3. Build a minimal proof of concept with two isolated agents: one coding agent and one independent reviewer.
4. Connect GitHub Actions as the mandatory validation gate.
5. Expand to frontend, backend, security, and QA roles only after the two-agent proof of concept is stable.
