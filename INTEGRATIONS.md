# HexStrike AI — CI/CD & Local LLM Integration (OpenAI-compatible)

This document describes the integrations added to this repo:

1. **CI/CD (GitLab)** — build, smoke test, and push images to a private registry.
2. **Local LLM agent (vLLM)** — drives 100+ HexStrike tools using a self-hosted
   OpenAI-compatible model, without Claude/Cursor.
3. **Security gate in your app pipeline** — code-scan (pre-deploy) + pentest
   (post-deploy), plus an on-demand webhook trigger.

---

## 1. Architecture at a glance

```
                    ┌────────────────────────┐
 Your local LLM     │  hexstrike_openai_agent │   spawn (stdio)
 (vLLM /v1) ◀──────▶│  .py  (agent loop)      │─────────────┐
 function-calling   └────────────────────────┘             ▼
                                                 ┌────────────────────┐
                                                 │  hexstrike_mcp.py   │  (MCP bridge)
                                                 └─────────┬──────────┘
                                                           │ HTTP REST
                                                           ▼
                                                 ┌────────────────────┐
                                                 │ hexstrike_server.py │  Flask :8888
                                                 │  + 150+ tools       │
                                                 └────────────────────┘
```

The agent pulls the tool list straight from the MCP bridge, so **any new tool
added to `hexstrike_mcp.py` is automatically available** to the model — no agent
change required.

---

## 2. Local LLM integration (vLLM)

### 2.1 Start a vLLM server with function-calling ENABLED

Function-calling must be enabled so the model can call tools:

```bash
vllm serve Qwen/Qwen2.5-7B-Instruct \
    --enable-auto-tool-choice \
    --tool-call-parser hermes          # adjust: hermes | llama3_json | mistral | ...
# OpenAI endpoint: http://<host>:8000/v1
```

> Choose a model that supports tool/function-calling (Qwen2.5-Instruct,
> Llama-3.1-Instruct, Mistral, etc.). A model without tool-calling support
> cannot execute tools.

### 2.2 Configuration

```bash
cp .env.example .env
# edit .env:
#   OPENAI_BASE_URL=http://<vllm-host>:8000/v1
#   OPENAI_MODEL=Qwen/Qwen2.5-7B-Instruct
#   OPENAI_API_KEY=EMPTY
```

### 2.3 Running

**A. Without Docker (local):**
```bash
pip install -r requirements.txt
python3 hexstrike_server.py --port 8888          # terminal 1

export OPENAI_BASE_URL=http://localhost:8000/v1
export OPENAI_MODEL=Qwen/Qwen2.5-7B-Instruct
python3 hexstrike_openai_agent.py "Do light recon on scanme.nmap.org"   # terminal 2
# or interactive REPL:
python3 hexstrike_openai_agent.py
```

**B. With docker-compose:**
```bash
docker compose -f deploy/docker-compose.yml up -d hexstrike-server
docker compose -f deploy/docker-compose.yml run --rm agent "Scan common ports on a-target-i-own.example"
docker compose -f deploy/docker-compose.yml run --rm agent            # interactive mode
```
> vLLM is assumed to run outside this compose (e.g. on a GPU host). From a
> container, the host is reachable via `host.docker.internal` (already mapped in compose).

### 2.4 Useful agent flags/ENV
| ENV | Flag | Default | Purpose |
|-----|------|---------|---------|
| `OPENAI_BASE_URL` | `--base-url` | `http://localhost:8000/v1` | vLLM endpoint |
| `OPENAI_MODEL` | `--model` | *(required)* | Model name |
| `OPENAI_API_KEY` | `--api-key` | `EMPTY` | Key (vLLM usually needs none) |
| `HEXSTRIKE_SERVER` | `--server` | `http://localhost:8888` | Flask API |
| `HEXSTRIKE_MAX_STEPS` | `--max-steps` | `20` | Max tool iterations per task |
| `HEXSTRIKE_TEMPERATURE` | `--temperature` | `0.2` | Sampling |
| `HEXSTRIKE_MAX_TOOL_CHARS` | — | `12000` | Cap on tool output fed to the model |

---

## 3. CI/CD integration (GitLab) — building the images

File: [`.gitlab-ci.yml`](.gitlab-ci.yml)

### 3.1 What runs
| Trigger | Jobs |
|---------|------|
| MR / any branch | `lint:python`, `lint:dockerfile` (hadolint), `check:dockerfile` (`docker build --check`) |
| Push to default branch | build + smoke test + push 3 images `:<sha>` & `:edge` (full, `-predeploy`, `-postdeploy`) |
| Push a git tag (e.g. `v6.0.1`) | build + smoke test + push 3 images `:<tag>` & `:latest` (full, `-predeploy`, `-postdeploy`) |

The three images are built in parallel (`parallel:matrix`): **full** (`deploy/Dockerfile`),
**pre-deploy** (`deploy/Dockerfile.predeploy`), **post-deploy** (`deploy/Dockerfile.postdeploy`).
Builds do **not** run on MRs to keep pipelines fast; only lightweight validation.

### 3.2 CI/CD Variables to set
`Settings → CI/CD → Variables`:

| Variable | Example | Notes |
|----------|---------|-------|
| `REGISTRY_IMAGE` | `registry.example.com/security/hexstrike-ai` | image path (required for a private registry) |
| `REGISTRY` | `registry.example.com` | registry host |
| `REGISTRY_USER` | `ci-pusher` | *masked* |
| `REGISTRY_PASSWORD` | `••••••` | *masked, protected* |

> If you use the built-in GitLab Container Registry, all four may be left empty —
> the pipeline falls back to `$CI_REGISTRY*`.

### 3.3 Runner requirements
- A **docker** executor with the **docker-in-docker** service (`docker:27-dind`).
- The **full-arsenal** image is ~15–25 GB → needs a self-managed runner with a
  large disk (job `timeout: 3h`). The **pre-deploy** & **post-deploy** images are
  much smaller and cloud-runner friendly — for the code-scan/pentest flow those
  two are enough, the full image is optional (used by the LLM agent). You can
  remove the full variant from `.image_matrix` if you don't need it.

### 3.4 Release example
```bash
git tag v6.0.1
git push origin v6.0.1     # triggers build:release -> pushes :v6.0.1 and :latest
```

---

## 4. Using HexStrike as a security gate in YOUR application pipeline

This is your primary use case: inserting HexStrike as a **security gate** into
your application pipeline — check the code before deploy, pentest after deploy.

### 4.1 Prerequisites
1. The HexStrike images are built & present in your private registry
   (see section 3 — the pipeline in this repo builds & pushes them).
2. Your GitLab runner can pull those images.

### 4.2 Include the template in your application `.gitlab-ci.yml`
```yaml
include:
  - project: 'security/hexstrike-ai'          # repo that hosts this template
    ref: master
    file: '/ci/hexstrike-scan.gitlab-ci.yml'

stages: [build, test, deploy, dast]

variables:
  HEXSTRIKE_PREDEPLOY_IMAGE: registry.example.com/security/hexstrike-ai:predeploy
  HEXSTRIKE_POSTDEPLOY_IMAGE: registry.example.com/security/hexstrike-ai:postdeploy
  HEXSTRIKE_FAIL_ON: high                       # none|low|medium|high|critical
  HEXSTRIKE_PENTEST_TARGET: https://staging.my-app.example
  HEXSTRIKE_USE_LLM: "false"                    # "true" for an AI summary (vLLM)

# pentest needs the deployed URL -> run after your deploy job
hexstrike_pentest:
  needs: ["deploy_staging"]
```

The template provides these jobs:

| Job | Image | When | Tools | Gate |
|-----|-------|------|-------|------|
| `hexstrike_code_scan` (stage `test`) | pre-deploy | before deploy | trivy fs (dependency CVEs, secrets, misconfig), checkov (IaC), semgrep (SAST), gitleaks (secrets) | fails if findings ≥ `HEXSTRIKE_FAIL_ON` |
| `hexstrike_pentest` (stage `dast`) | post-deploy | after deploy | wafw00f, httpx, nuclei, nikto (`full` profile) against the URL | fails if findings ≥ `HEXSTRIKE_FAIL_ON` |
| `lint_python`/`lint_js`/`lint_go`/`lint_shell`/`lint_dockerfile` (stage `test`) | language image | code quality | ruff / eslint / golangci-lint / shellcheck / hadolint | advisory (`allow_failure: true`) |

The linter jobs **auto-enable** per language (`rules: exists`) and run in each
language's lightweight image (not the HexStrike image). To block the pipeline on
lint issues, override e.g. `lint_python: { allow_failure: false }` in the caller pipeline.

Reports `hexstrike-reports/hexstrike-{code-scan,pentest}.{json,md}` are archived
as artifacts (30-day retention).

### 4.3 Webhook trigger (post-deploy, on demand)

Besides the CI jobs, the **post-deploy** image bundles
[`hexstrike_webhook.py`](hexstrike_webhook.py) to trigger scans from outside the
pipeline (e.g. called by your CD system after a deploy) with a target + creds:

```bash
export WEBHOOK_TOKEN=$(openssl rand -hex 16)
docker compose -f deploy/docker-compose.yml --profile webhook up -d pentest-webhook

curl -X POST http://localhost:9000/trigger \
  -H "X-Webhook-Token: $WEBHOOK_TOKEN" -H "Content-Type: application/json" \
  -d '{"target":"https://staging.example","action":"pentest","profile":"quick",
       "auth":{"type":"bearer","token":"eyJ..."}}'
# -> {"job_id":"...","status":"accepted"}   ; check: GET /status/<job_id>
```

- Request auth: `WEBHOOK_TOKEN` (header `X-Webhook-Token`) or `WEBHOOK_HMAC_SECRET`
  (`X-Hub-Signature-256`). Without either, `/trigger` rejects everything.
- The `auth` creds (bearer/basic/cookie/header) are used for **authenticated scans**;
  they are passed to the scanner via env (not logged, not visible in the process list).
- The target is validated to reject shell metacharacters.

### 4.4 How it works inside a job
Each job runs **inside a HexStrike image**, starts the Flask server in the
background, then [`hexstrike_ci.py`](hexstrike_ci.py) calls its REST API:
- `code-scan`: the server and the repo live in the same container, so
  `trivy fs $CI_PROJECT_DIR` actually scans your code.
- `pentest`: hits `HEXSTRIKE_PENTEST_TARGET` (staging/prod URL).

The gate is **deterministic** (based on tool findings, not the LLM). `--use-llm`
only adds a triage summary written by your vLLM to the `.md` report (advisory).

### 4.5 Run locally (no CI, for a quick test)
```bash
python3 hexstrike_server.py --port 8888 &                 # or use the container image
python3 hexstrike_ci.py --fail-on high code-scan --path .
python3 hexstrike_ci.py --fail-on high pentest --target https://staging.example --profile quick
```

### 4.7 Remote / endpoint mode (HexStrike on a VPS, called from CI)

Instead of running a HexStrike image *inside* each CI job, you can run HexStrike
as **long-running services on a VPS** and have the GitLab runner just **call the
endpoints**. The jobs then run in a tiny `alpine` image (curl+jq+tar).

**Endpoints (both images ship [`hexstrike_webhook.py`](hexstrike_webhook.py)):**

| Image / service | Port | Endpoint | Input |
|-----------------|------|----------|-------|
| pre-deploy (code-scan) | 9001→9000 | `POST /scan/code` | multipart repo archive (`file=@repo.tgz`) + `fail_on` |
| post-deploy (pentest) | 9000 | `POST /trigger` | JSON `{target, action, profile, fail_on, auth?}` |
| both | — | `GET /status/<job_id>`, `GET /jobs`, `GET /health` | — |

Both return `{job_id}`; poll `GET /status/<job_id>` until `status=completed`,
then read `gate_failed` (the gate is computed server-side from findings vs `fail_on`).

**1) Deploy on the VPS** ([`deploy/docker-compose.vps.yml`](deploy/docker-compose.vps.yml)):
```bash
export REGISTRY_IMAGE=registry.example.com/security/hexstrike-ai
export WEBHOOK_TOKEN=$(openssl rand -hex 24)
docker compose -f deploy/docker-compose.vps.yml pull
docker compose -f deploy/docker-compose.vps.yml up -d
# code-scan -> http://<vps>:9001 , pentest -> http://<vps>:9000
```
> Put both behind a **TLS reverse proxy** and restrict to your GitLab runner IPs.
> `WEBHOOK_TOKEN` (or `WEBHOOK_HMAC_SECRET`) is required. Using **Nginx Proxy
> Manager** (on a separate VM)? See [`deploy/NPM-SETUP.md`](deploy/NPM-SETUP.md) —
> and remember to raise `client_max_body_size` (≥ `HEXSTRIKE_MAX_UPLOAD_MB`) or
> code-archive uploads fail with `413`.

**2) In your application `.gitlab-ci.yml`**, include the remote template
([`ci/hexstrike-remote.gitlab-ci.yml`](ci/hexstrike-remote.gitlab-ci.yml)):
```yaml
include:
  - project: 'security/hexstrike-ai'
    ref: master
    file: '/ci/hexstrike-remote.gitlab-ci.yml'

stages: [build, test, deploy, dast]

variables:
  HEXSTRIKE_CODESCAN_URL: https://codescan.hexstrike.example.com   # NPM -> VPS :9001
  HEXSTRIKE_PENTEST_URL:  https://pentest.hexstrike.example.com    # NPM -> VPS :9000
  HEXSTRIKE_PENTEST_TARGET: https://staging.my-app.example
  HEXSTRIKE_FAIL_ON: high

hexstrike_pentest:
  needs: ["deploy_staging"]
```
Set the masked CI/CD variable **`HEXSTRIKE_WEBHOOK_TOKEN`** = the VPS `WEBHOOK_TOKEN`.

- `hexstrike_code_scan` (stage `test`): tars the repo, uploads to `/scan/code`,
  polls, and fails the job if `gate_failed`.
- `hexstrike_pentest` (stage `dast`): POSTs `/trigger` with the deployed URL,
  polls, and fails the job if `gate_failed`.

**Manual test with curl:**
```bash
# code-scan
tar czf repo.tgz --exclude=.git --exclude=node_modules .
curl -s -X POST https://codescan.hexstrike.example.com/scan/code \
  -H "X-Webhook-Token: $TOKEN" -F "file=@repo.tgz" -F "fail_on=high"
# -> {"job_id":"...","status":"accepted"} ; then GET /status/<job_id>

# pentest
curl -s -X POST https://pentest.hexstrike.example.com/trigger \
  -H "X-Webhook-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"target":"https://staging.example","action":"pentest","profile":"quick","fail_on":"high"}'
```

Full JSON/Markdown reports remain on the VPS under `hexstrike-reports/<job_id>/`;
the `/status` response returns severity counts and the gate result.

### 4.8 Metric dashboard (SQLite-backed)

Every completed job is persisted to a **SQLite** DB
(`/opt/hexstrike-ai/hexstrike-reports/hexstrike.db`, on a persistent volume) and
surfaced as a metric dashboard on the **same webhook port**:

| Endpoint | What |
|----------|------|
| `GET /dashboard` | metric dashboard (KPIs, findings-by-severity, 14-day trend, top targets, recent runs) — auto-refresh 30s |
| `GET /dashboard/<run_id>` | single report detail (per-severity KPIs + full findings table) |
| `GET /api/metrics` | aggregate metrics as JSON |
| `GET /api/reports` / `/api/reports/<id>` | recent list / one report (by `run_id` or `job_id`) as JSON |

Auth: if `WEBHOOK_TOKEN` is set, the dashboard/API require the token via header
`X-Webhook-Token` **or** query `?token=<WEBHOOK_TOKEN>` (browser-friendly — links
carry the token). If no token is configured it is open (dev only). In production
also restrict it at the reverse proxy (NPM Access List).

```bash
# open in a browser (behind NPM this is https://codescan.hexstrike.example.com/dashboard?token=...)
curl "http://<vps>:9001/dashboard?token=$WEBHOOK_TOKEN"
curl "http://<vps>:9001/api/metrics?token=$WEBHOOK_TOKEN"
```

Persistence: the DB lives on the `codescan_reports` / `pentest_reports` volumes
(declared via `VOLUME` in the images and named volumes in the compose files), so
dashboard history survives container restarts/upgrades. Each service has its own
DB (code-scan service shows code-scans; pentest service shows pentests).

### 4.6 About "code quality" — honest scope
HexStrike is a **pentest/security** framework, not a *code quality* tool. What it
can do to code is **security**: dependency CVEs, secrets, IaC misconfig, semgrep
SAST patterns. It does **not** replace language linters/formatters or quality
gates like SonarQube/ESLint/pylint/golangci-lint.

Recommendation: use HexStrike for *security checks*, and keep running your
language linters (the `lint_*` jobs) for pure *code quality*.

---

## 5. Security / operational notes
- The agent and pentest jobs can execute real offensive tools. Only run them
  against assets you own or are authorized to test; restrict the container's
  network if needed.
- `cap_add: NET_RAW/NET_ADMIN` in compose is required by tools like `nmap -sS`,
  `masscan`, `arp-scan`. Remove them if not needed.
- Do not commit `.env` (it holds internal endpoints/hosts). It is already ignored
  from the build context and via `.gitignore`.
- Set `WEBHOOK_TOKEN` (or `WEBHOOK_HMAC_SECRET`) for the webhook; without it,
  `/trigger` refuses all requests.

---

## 6. Code structure — `hexstrike_lib/` package

The integration layer is organized as small single-responsibility modules under
`hexstrike_lib/`. The top-level scripts are **thin entrypoints** (≤ 20 lines) so
the Dockerfiles/compose that run them stay unchanged.

**Entrypoints (repo root):**

| Script | Delegates to |
|--------|--------------|
| `hexstrike_ci.py` | `hexstrike_lib.cli:main` |
| `hexstrike_webhook.py` | `hexstrike_lib.webhook_app:main` |
| `hexstrike_openai_agent.py` | `hexstrike_lib.agent:main` |
| `hexstrike_mcp.py` | `hexstrike_lib.mcp.server:main` |
| `hexstrike_db.py` | compat shim → `hexstrike_lib.db` + `hexstrike_lib.dashboard` |
| `hexstrike_server.py` | unchanged upstream monolith (not refactored) |

**Modules (`hexstrike_lib/`):**

| Area | Module | Responsibility |
|------|--------|----------------|
| shared | `severity.py` | severity order, ranking, colors (single source) |
| | `config.py` | env-based configuration |
| | `logging_util.py` | log helper |
| CI scanner | `client.py` | HexStrike REST client |
| | `findings.py` | finding model + severity counts |
| | `parsers.py` | trivy/checkov/nuclei output parsers |
| | `local_tools.py` | semgrep/gitleaks local CLI runners |
| | `ai_summary.py` | optional LLM triage summary |
| | `reporting.py` | write JSON/MD reports + gating |
| | `scanners.py` | code_scan & pentest orchestration |
| | `cli.py` | CI command-line interface |
| storage/UI | `db.py` | SQLite report store |
| | `dashboard.py` | HTML dashboard renderer |
| webhook | `auth.py` | request/view authorization (token/HMAC) |
| | `auth_headers.py` | build auth headers for authenticated scans |
| | `archive.py` | safe archive extraction (upload) |
| | `jobs.py` | `JobManager` background job runner |
| | `server_control.py` | autostart hexstrike_server |
| | `webhook_app.py` | Flask app factory + routes + main |
| agent | `agent.py` | OpenAI-compatible (vLLM) agent via MCP |
| MCP bridge | `mcp/colors.py` | color palette + colored logging formatter |
| | `mcp/client.py` | REST client for the MCP bridge |
| | `mcp/server.py` | assembles FastMCP + registers tool categories + `main` (thin) |
| | `mcp/tools/<cat>.py` | per-category `@mcp.tool` registrations via `register(mcp, client)` — 14 modules (network, cloud, web, binary, api, ctf, recon, intelligence, visual, process, monitoring, python_env, files_payloads, additional) |
| server: runtime | `server/execution.py` | `execute_command`(+recovery) + `EnhancedCommandExecutor` + process/cache/telemetry infra + runtime singletons (cache, telemetry, error_handler, …) — the "unlock" that breaks circular imports |
| | `server/context.py` | registry of non-execution singletons (decision_engine, cve_intelligence, exploit_generator, …) |
| | `server/deps.py` | shared namespace for blueprints (`from ...deps import *`) — re-exports singletons, classes, execute_command, Flask utils |
| | `server/scan_helpers.py` | `execute_*_scan` helpers used by smart-scan |
| server: subsystems | `server/models.py` | data models — enums & dataclasses |
| | `server/decision_engine.py` | `IntelligentDecisionEngine` |
| | `server/errors.py` | `IntelligentErrorHandler` + `GracefulDegradation` |
| | `server/analyzers.py` | TechnologyDetector, RateLimitDetector, FailureRecoverySystem, PerformanceMonitor, ParameterOptimizer |
| | `server/bugbounty.py` | BugBountyTarget, BugBountyWorkflowManager, FileUploadTestingFramework |
| | `server/visual.py` | `ModernVisualEngine` |
| | `server/ctf.py` | CTF workflow / tooling / automation / team managers |
| | `server/cve_intel.py` | `CVEIntelligenceManager` |
| | `server/correlator.py` | `VulnerabilityCorrelator` |
| | `server/file_ops.py` | `FileOperationsManager` |
| | `server/http_framework.py` | `HTTPTestingFramework` |
| | `server/browser_agent.py` | `BrowserAgent` (Selenium) |
| | `server/exploits.py` | `AIExploitGenerator` (AV-gated payload templates) |
| | `server/payload_generator.py` | `AIPayloadGenerator` (AV-gated) |
| server: routes | `server/routes/{core,tools1,tools2,tools3,misc}.py` | 156 REST endpoints split into 5 Flask Blueprints |
| | `server/routes/__init__.py` | `register_all(app)` — registers every blueprint |

Guiding rule: each file has one reason to change. E.g. adjusting the trivy parser
touches only `parsers.py`; changing the dashboard look touches only `dashboard.py`;
adding an MCP tool touches only the relevant `mcp/tools/<category>.py`; adding a REST
endpoint touches only the relevant `server/routes/*.py`.

> `hexstrike_server.py` (the upstream Flask server) has been **fully modularized**:
> the ~17.3k-line monolith is now an **83-line bootstrap** (create app → import subsystems →
> `routes.register_all(app)` → `main()`). All 156 REST endpoints live in 5 Blueprints under
> `server/routes/`, the `execute_command` execution core in `server/execution.py`, singletons
> in `server/context.py`, and every class in its own `server/*.py`. The AV-sensitive exploit/
> payload templates (`exploits.py`, `payload_generator.py`) require a Windows Defender folder
> exclusion to sit in isolated files. Validation for every stage: import the server (all 156
> routes register, all singletons construct), a broad runtime smoke across all 5 blueprints
> (0 NameErrors), and end-to-end predeploy/postdeploy image runs (server healthy, scan completes).
