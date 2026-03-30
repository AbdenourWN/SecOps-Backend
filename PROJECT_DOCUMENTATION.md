# SecOps-Backend — Project Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture & Design Decisions](#architecture--design-decisions)
3. [Development Timeline](#development-timeline)
4. [Phase 1 — Foundation (Feb 2–16)](#phase-1--foundation-feb-216)
5. [Phase 2 — Detection & Automation (Mar 12–25)](#phase-2--detection--automation-mar-1225)
6. [Phase 3 — Elasticsearch Integration (Mar 26–28)](#phase-3--elasticsearch-integration-mar-2628)
7. [Current Architecture](#current-architecture)
8. [Known Issues & Decisions](#known-issues--decisions)
9. [Performance Optimization Plan](#performance-optimization-plan)

---

## Project Overview

**SecOps-Backend** is an intelligent Security Operations automation platform that monitors servers, collects logs and metrics, detects security threats using regex-based rules, and automatically remediates them — all without installing agents on the monitored servers.

**Core Value Proposition**: Agentless architecture. The app connects to servers via SSH (Linux) and WinRM (Windows) to collect data, run commands, and execute remediation scripts. No software installation is required on the target servers.

### Technology Stack

| Layer | Technology | Role |
|---|---|---|
| Framework | **FastAPI** | Async REST API |
| Structured Data | **MongoDB** (Motor async driver) | Servers, credentials, rules, scripts, incidents |
| Time-Series Data | **Elasticsearch** | Logs and metrics (full-text search, aggregations) |
| SSH Client | **Paramiko** | Linux server communication |
| Windows Client | **pywinrm** | Windows server communication (WinRM/WS-Management) |
| Scheduler | **APScheduler** | Background jobs (log collection, health checks, metrics) |
| Security | **cryptography** (Fernet) | Credential encryption at rest |
| Containerization | **Docker Compose** | Elasticsearch + Kibana for development |

---

## Architecture & Design Decisions

### Modular Monolith

The project follows a **modular monolith** pattern — a single FastAPI app with clearly separated modules. Each module has its own `router.py`, `service.py`, and `schemas.py`. This structure allows the codebase to grow without becoming spaghetti, while avoiding the overhead of microservices.

```
app/
├── core/                    # Shared infrastructure
│   ├── config.py            # Environment settings (Pydantic)
│   ├── database.py          # MongoDB connection manager
│   ├── elasticsearch.py     # Elasticsearch connection manager
│   ├── executors.py         # SSH/WinRM executor factory
│   ├── scheduler.py         # APScheduler background jobs
│   └── security.py          # Fernet encryption for credentials
│
├── modules/                 # Feature modules
│   ├── servers/             # Server CRUD + health checks
│   ├── logs/                # Log collection + file watcher
│   ├── metrics/             # CPU/RAM/disk collection
│   ├── analysis/            # Rule engine + detection
│   ├── automation/          # Remediation scripts + execution
│   ├── incidents/           # Incident lifecycle management
│   ├── dashboard/           # Aggregated stats endpoints
│   ├── test/                # Simulation endpoints
│   └── users/               # (Planned) Authentication
│
├── main.py                  # App entrypoint + lifecycle
└── docker-compose.yml       # ES + Kibana
```

### Database Strategy

The initial approach stored **everything** in MongoDB — logs, metrics, incidents, rules, servers. This worked for prototyping but had clear problems:

1. **Logs grow fast**: Each server produces hundreds of log lines per collection cycle. MongoDB doesn't have efficient full-text search built-in.
2. **Metrics are time-series**: MongoDB can store metrics, but querying "last 20 data points for server X sorted by time" is not what MongoDB is optimized for.
3. **Search**: There was no way to search logs by content (e.g., "find all logs containing 'failed password'").

**Decision**: Move logs and metrics to **Elasticsearch**, keep everything else in MongoDB.

| Data Type | Storage | Rationale |
|---|---|---|
| Servers, credentials, rules, scripts, incidents | **MongoDB** | Structured CRUD data with relationships |
| Logs | **Elasticsearch** | Full-text search, high volume, monthly index rotation |
| Metrics | **Elasticsearch** | Time-series queries, avoids MongoDB bloat |

This keeps the stack at 2 databases (not 3), since ES handles both logs and metrics well at this scale. InfluxDB/Prometheus would be "correct" for metrics in pure production, but adding a 3rd database was unnecessary complexity.

### Agentless vs Agent-Based

The project deliberately chose **agentless collection** (SSH into servers) over installing agents (like Filebeat/Metricbeat) because:

1. **Zero server-side setup** — no packages to install, no configs to maintain on target machines
2. **Full control** — the collection logic lives in one place (the backend), not scattered across agents
3. **Educational value** — demonstrates understanding of SSH, WinRM, log parsing, and system commands

The tradeoff is performance at scale — agent-based approaches push data to centralized storage, while agentless requires pulling. For 50+ servers in production, Filebeat/Logstash would be the recommended migration path. Both approaches can coexist since they write to the same ES indices.

---

## Development Timeline

### Phase 1 — Foundation (Feb 2–16)

The first two weeks focused on building the core CRUD operations and establishing the data collection pipeline.

#### Day 1: Project Scaffolding (Feb 2)

**Commits**: `d2ddf96` → `2107e50`

Set up the project structure: FastAPI with `uvicorn`, MongoDB with `motor` async driver, Pydantic for validation, and `python-dotenv` for configuration. The directory structure followed a modular monolith pattern from the start — each feature area (servers, logs, etc.) gets its own directory with `router.py`, `service.py`, and `schemas.py`.

The MongoDB connection uses a singleton pattern (`Database` class + `get_database()` function) that connects on app startup and closes on shutdown. This pattern was later mirrored for Elasticsearch.

#### Day 1 (continued): SSH Execution & Server CRUD

**Commits**: `29f2bee` → `accb1b2`

Built the SSH command execution layer using **Paramiko**. The design decision here was important: credentials are encrypted with Fernet symmetric encryption before storage (`security.py` → `encrypt_password()` / `decrypt_password()`). Passwords never exist in plaintext in the database.

Server CRUD includes a **verify_ownership** mechanism — to update or delete a server, you must provide the current password. This prevents unauthorized modifications even without full authentication.

#### Day 2: Health Monitoring (Feb 3)

**Commits**: `4d04d1c` → `ad6d133`

Implemented "The Watcher" — a background health check system using APScheduler. Every 30 seconds, the scheduler iterates through all servers and pings their SSH/WinRM port to determine online/offline status.

Key design choice: `executors.py` implements a **Factory Pattern**. The function `get_server_executor(server, password)` returns either a `LinuxExecutor` or `WindowsExecutor` based on `server.os_type`. Both implement the same interface (`run_command()`, `check_health()`), so the rest of the codebase doesn't care about OS differences.

```python
# The factory hides OS complexity from the rest of the app
executor = get_server_executor(server, plain_password)
result = await executor.run_command(command)  # Works for both Linux and Windows
```

#### Day 3: Log Collection Module (Feb 5)

**Commits**: `35cc64d` → `f09add5`

Built the log collection pipeline:

- **Linux**: Runs `journalctl --output=json --no-pager -p 4 --since "5 minutes ago"` to get system logs at Warning level and above. Each JSON line is parsed, deduplicated, and stored.
- **File Watcher**: A separate `FileWatcherService` that tracks file offsets in a `logSources` collection. It SSHes into the server, reads from the last-known offset using `tail -c +{offset}`, and stores new lines. This handles log files like `/var/log/nginx/access.log`.

Deduplication was initially done via a MongoDB query per log line — checking if a document with the same `server_id + timestamp + message` already exists. This worked for small volumes but was identified as a bottleneck later.

#### Week 2: Windows Integration & Metrics (Feb 11–16)

**Commits**: `3567c0d` → `e45b8dd`

Added Windows server support via **pywinrm** (WS-Management protocol). The executor factory was extended:

- **Windows Logs**: PowerShell command `Get-WinEvent` with JSON output, filtered for Warning/Error/Critical from System, Security, and Application log channels.
- **Windows Metrics**: PowerShell commands for `Win32_Processor` (CPU), `Win32_OperatingSystem` (RAM), and `Win32_LogicalDisk` (Disk).
- **Linux Metrics**: Bash one-liners parsing `/proc/stat` (CPU), `free` (RAM), and `df` (Disk).

A PowerShell quirk was discovered during this phase: `ConvertTo-Json` returns a JSON object for 1 result but a JSON array for 2+ results. The parser handles both cases by wrapping single objects in `[]`.

Added MongoDB compound indexes for performance:
- `logs`: `(server_id ASC, timestamp DESC)` — fast per-server log queries
- `metrics`: `(server_id ASC, timestamp DESC)` — fast per-server metric history

---

### Phase 2 — Detection & Automation (Mar 12–25)

After a gap (likely working on other components), the focus shifted to the **intelligence layer** — making the app detect threats and respond automatically.

#### Rule-Based Detection Engine

**Commit**: `1c1ed8d`, `2dac05d`

The analysis engine (`analysis/service.py`) implements a **3-level response system**:

| Level | Name | Behavior |
|---|---|---|
| 1 | Auto-Fix | Detect → Create incident → Execute remediation script → Auto-resolve if successful |
| 2 | Fix + Alert | Detect → Create incident → Execute script → Send notification (pending) |
| 3 | Alert Only | Detect → Create incident → Send notification (pending) |

The detection loop works as follows:

1. Fetch all enabled rules from MongoDB
2. Pre-compile regex patterns (done once per batch, not per log)
3. Filter rules by OS type (Linux rules don't run against Windows logs)
4. For each log message, test against each active rule's compiled regex
5. On match: extract named groups from the regex as context variables (e.g., `source_ip`, `username`)
6. Create an incident with the extracted context
7. If Level 1/2: execute the linked remediation script with variable substitution

#### Dynamic Remediation Scripts

Six default scripts are seeded at startup (`automation/service.py` → `seed_default_scripts()`):

| Script Name | Command | Variables |
|---|---|---|
| Block IP (iptables) | `iptables -A INPUT -s {{source_ip}} -j DROP` | `source_ip` |
| Kill Process by PID | `kill -9 {{process_id}}` | `process_id` |
| Restart Service | `systemctl restart {{service_name}}` | `service_name` |
| Clear Temp Files | `find /tmp -type f -mtime +7 -delete` | — |
| Block Windows IP | `netsh advfirewall ... {{source_ip}} ...` | `source_ip` |
| Force Logoff User | `query user ... {{username}} ...` | `username` |

**Variable substitution** uses `{{key}}` template syntax. When a rule detects a pattern like `Failed password .* from (?P<source_ip>\d+\.\d+\.\d+\.\d+)`, the captured `source_ip` (e.g., `10.99.99.1`) is injected into the script command: `iptables -A INPUT -s 10.99.99.1 -j DROP`.

#### Rule ↔ Script Dynamic Linking

Rules reference scripts **by name**, not by MongoDB ObjectId. At startup, `seed_default_rules()` resolves script names to their actual `_id` values. This means:

1. Scripts are seeded first (guaranteed to exist)
2. Rules are seeded second (look up script IDs by name)
3. If a script doesn't exist yet, the rule is created without a `remediation_script_id`

This approach avoids hardcoded IDs that would break across environments.

#### Incident Management Module

Created `app/modules/incidents/` with full CRUD:

- `GET /api/incidents` — list with filters (server_id, severity, status)
- `GET /api/incidents/{id}` — detail view
- `PATCH /api/incidents/{id}` — update status (open → investigating → resolved / false_positive)
- `GET /api/incidents/stats` — aggregated counts by severity and status

#### Dashboard APIs

Created `app/modules/dashboard/` with three endpoints:

- `GET /api/dashboard/summary` — cross-module stats (server counts, incident breakdown, log volume, rule/script counts)
- `GET /api/dashboard/recent-incidents` — latest incidents enriched with server hostnames
- `GET /api/dashboard/server-health` — all servers with their latest metric snapshot + open incident count

#### Test Simulation Module

Created `app/modules/test/` to enable end-to-end pipeline testing without needing real security events:

- `POST /api/test/simulate` — injects fake system logs via `logger` (Linux) / `Write-EventLog` (Windows) on the actual VMs using safe IPs (`10.99.99.x`)
- `POST /api/test/simulate/file-logs` — creates test log files and auto-registers them as `logSource` entries

This module proved critical for validating the full detection → incident → remediation pipeline without manually generating security events.

---

### Phase 3 — Elasticsearch Integration (Mar 26–28)

The MongoDB-only approach had reached its limits:

1. No full-text log search capability
2. The `logs` and `metrics` collections were growing unbounded
3. Time-range queries on logs were slow without proper indexing

#### Thought Process

The initial plan considered **dual-write** (writing to both MongoDB and ES). After discussion, the decision was to go **ES-only for logs** — MongoDB adds no value for unstructured log data. The analysis engine already receives logs in-memory (as a Python list), so it doesn't need to query them from any database.

Several pre-built tools were also evaluated:

| Tool | What It Does | Decision |
|---|---|---|
| **Filebeat** | Agent on each server, pushes logs to ES | Deferred — breaks the agentless design, but noted as a production alternative |
| **Logstash** | Log parsing pipeline (500+ built-in parsers) | Deferred — the custom parser works well for the current rule set |
| **Metricbeat** | Agent for metric collection | Deferred — same reason as Filebeat |

These were documented in the roadmap as future migration paths for 50+ server deployments.

#### What Changed

**New Files**:
- `docker-compose.yml` — Single-node Elasticsearch 8.13 + Kibana, with `ES_JAVA_OPTS=-Xms512m -Xmx512m` memory limit
- `app/core/elasticsearch.py` — Connection manager with index templates for both logs and metrics

**Modified Files**:
- `app/core/config.py` — Added `ELASTICSEARCH_URL` setting with default
- `app/main.py` — Wired ES connect/close into the app lifecycle
- `app/modules/logs/service.py` — **Full rewrite**: MongoDB insert → ES `es.index()`, MongoDB dedup → ES search, MongoDB `get_logs()` → ES search
- `app/modules/logs/router.py` — Added `GET /api/logs/search` with full-text query, server_id, level, and date range filters
- `app/modules/metrics/service.py` — Metrics now index to ES instead of MongoDB
- `app/modules/dashboard/service.py` — Log stats and server health metrics now query ES
- `requirements.txt` — Added `elasticsearch[async]>=8.0.0,<9.0.0`

**Key ES Concepts Used**:
- **Monthly indices** (`secops-logs-2026.03`, `secops-metrics-2026.03`) — easy retention management, just delete old indices
- **Index templates** — auto-applied mappings for new indices matching `secops-logs-*` or `secops-metrics-*`
- **Text vs Keyword fields** — `message` is `text` (analyzed for word-level search), `server_id` / `level` are `keyword` (exact match only)
- **Bool queries with filter context** — exact matches without relevance scoring (fast)

**Version Issue Encountered**: The Python `elasticsearch` library v9.x was installed via pip, but the ES server was v8.13.0. The v9 client sends `compatible-with=9` headers that v8 rejects. Fixed by pinning to `<9.0.0`.

**Port Reservation Issue**: Docker Desktop's Hyper-V reserves random port ranges on Windows. Port 8000 (uvicorn default) fell inside a reserved range (`7979–8078`), causing `[WinError 10013]`. Solved by using port 8500.

#### Metrics Migration (Additional Decision)

Initially, metrics were going to stay in MongoDB. After further consideration, the decision was made to move metrics to ES too — since ES was already running and handles time-series data well. This prevents MongoDB from being filled with high-frequency metric data that grows linearly with the number of servers × collection intervals.

---

## Current Architecture

### Data Flow

```
┌──────────────┐     SSH/WinRM      ┌──────────────────┐
│  Linux VMs   │◄───────────────────│                  │
│  Windows VMs │────────────────────│  FastAPI Backend  │
└──────────────┘   logs + metrics   │                  │
                                    │  ┌────────────┐  │
                                    │  │ Scheduler   │  │  Every 60s:
                                    │  │  (APSched)  │──│── collect_logs()
                                    │  └────────────┘  │── collect_metrics()
                                    │                  │── health_check()
                                    │  ┌────────────┐  │── file_watcher()
                                    │  │ Analysis   │  │
                                    │  │ Engine     │──│── regex match → incident
                                    │  └────────────┘  │── auto-remediate (Level 1/2)
                                    │                  │
                                    └────────┬─────────┘
                                             │
                              ┌──────────────┼──────────────┐
                              ▼              ▼              ▼
                        ┌──────────┐  ┌────────────┐  ┌──────────┐
                        │ MongoDB  │  │   Elastic   │  │  Kibana  │
                        │          │  │   Search    │  │  (UI)    │
                        │ servers  │  │             │  │          │
                        │ creds    │  │ secops-logs │  │ Browse   │
                        │ rules    │  │ secops-     │  │ ES data  │
                        │ scripts  │  │   metrics   │  │ visually │
                        │ incidents│  │             │  │          │
                        └──────────┘  └────────────┘  └──────────┘
```

### API Endpoints

| Module | Endpoint | Method | Description |
|---|---|---|---|
| **Servers** | `/api/servers` | GET | List all servers |
| | `/api/servers` | POST | Register a new server |
| | `/api/servers/{id}` | GET | Server details |
| | `/api/servers/{id}` | PUT | Update server (requires current password) |
| | `/api/servers/{id}` | DELETE | Delete server + credentials |
| | `/api/servers/{id}/execute` | POST | Execute command on server |
| **Logs** | `/api/logs/search` | GET | Full-text log search (ES-powered) |
| | `/api/logs/collect/{id}` | POST | Manually trigger log collection |
| | `/api/logs/{server_id}` | GET | Get logs for a server |
| | `/api/logs/sources` | POST | Register a file log source |
| | `/api/logs/sources/poll` | POST | Force check file sources |
| **Metrics** | `/api/metrics/{server_id}` | GET | Get metric history |
| | `/api/metrics/collect/{id}` | POST | Manually trigger metric collection |
| **Analysis** | `/api/analysis/rules` | GET/POST | CRUD detection rules |
| | `/api/analysis/rules/{id}` | GET/PUT/DELETE | Manage specific rule |
| **Automation** | `/api/automation/scripts` | GET/POST | CRUD remediation scripts |
| | `/api/automation/scripts/{id}` | GET/PUT/DELETE | Manage specific script |
| | `/api/automation/execute` | POST | Manually execute a script on a server |
| **Incidents** | `/api/incidents` | GET | List incidents (with filters) |
| | `/api/incidents/{id}` | GET/PATCH | View/update incident |
| | `/api/incidents/stats` | GET | Aggregated incident statistics |
| **Dashboard** | `/api/dashboard/summary` | GET | Full overview stats |
| | `/api/dashboard/recent-incidents` | GET | Latest incidents with hostnames |
| | `/api/dashboard/server-health` | GET | All servers + latest metrics |
| **Test** | `/api/test/simulate` | POST | Inject fake system logs on VMs |
| | `/api/test/simulate/file-logs` | POST | Create test file logs + auto-register sources |

---

## Known Issues & Decisions

### Remediation Permissions

Auto-remediation commands (`iptables`, `kill`, `find -delete`) fail because the SSH user doesn't have sudo privileges. Three fix options documented:

1. **Prefix with `sudo`** — requires passwordless sudo configured on target VMs
2. **SSH as root** — simpler but bad practice
3. **Use `sudo -S`** — pipe the password via stdin (already encrypted in DB)

**Status**: Deferred. Tracked for implementation during the Resilience phase.

### Filebeat / Logstash

Pre-built log collection tools evaluated and documented as future alternatives for 50+ server deployments. The custom agentless approach was deliberately chosen for control and educational value. Migration path is easy: Filebeat writes to the same `secops-logs-*` index format, so the search API and detection engine need zero changes.

---

## Performance Optimization Plan

A full code audit identified **6 critical optimizations** needed before the app can scale beyond a few servers.

### Current Bottlenecks

With 10 servers × 200 logs each, the current app makes:
- **4000+ HTTP requests** to Elasticsearch per scheduler cycle (200 dedup + 200 index per server)
- **500 seconds** to process all servers sequentially (exceeds the 60s scheduler interval)
- **10 MongoDB queries** per cycle to reload and recompile detection rules
- **Unlimited duplicate incidents** if scheduler cycles overlap

### Optimization 1: Semaphore-Based Parallel Scheduler

**Problem**: All scheduler jobs (`log_collection`, `metric_collection`, `health_check`, `file_watcher`) iterate through servers sequentially. One slow/offline server blocks all others.

**Solution**: Use `asyncio.Semaphore(N)` + `asyncio.gather()`. This runs up to N servers concurrently. When one finishes, the next starts. The semaphore limit prevents overwhelming the system with too many simultaneous SSH connections.

**Scalability**:
- 10 servers with `Semaphore(20)`: all 10 run at once → ~5s total
- 100 servers with `Semaphore(20)`: 5 batches of 20 → ~25s total
- 1000 servers with `Semaphore(20)`: 50 batches of 20 → ~250s total (configurable via `MAX_CONCURRENT_SERVERS` in `.env`)

**Files**: `scheduler.py`, `servers/service.py`, `config.py`

### Optimization 2: Bulk ES Indexing

**Problem**: `_index_to_es()` sends one HTTP request per log document. 200 logs = 200 HTTP requests with full TCP overhead each time.

**Solution**: Replace individual `es.index()` calls with `elasticsearch.helpers.async_bulk()`. Build all documents in a list first, then send them to ES in a single HTTP request.

**Files**: `logs/service.py`

### Optimization 3: O(1) Deduplication

**Problem**: `_check_exists_in_es()` runs one ES search per log line to check if it already exists. 200 logs = 200 search queries before indexing even begins.

**Solution**: Query ES once for the latest timestamp for that server. Then skip all logs with timestamps ≤ the latest — using a pure Python comparison, no network call. 200 queries → 1 query.

**Files**: `logs/service.py`

### Optimization 4: Cache Analysis Rules

**Problem**: `analyze_logs()` queries MongoDB for all enabled rules and re-compiles their regex patterns every time it's called (every 60 seconds, per server).

**Solution**: Module-level cache with a 5-minute TTL. Rules are fetched from MongoDB once, compiled once, and reused across all servers for 5 minutes. If a rule is updated, the cache refreshes on the next cycle.

**Files**: `analysis/service.py`

### Optimization 5: Duplicate Incident Prevention

**Problem**: No check exists before creating incidents. If the same log triggers the same rule in overlapping scheduler cycles, duplicate incidents are created.

**Solution**: Before creating an incident, check if one already exists for the same `server_id + rule_id` within the last 5 minutes. If so, skip creation.

**Files**: `analysis/service.py`

### Optimization 6: Dashboard N+1 Query Fix

**Problem**: `get_server_health()` runs 2 queries per server (1 ES search for latest metric + 1 MongoDB count for open incidents). 50 servers = 100 queries per page load.

**Solution**: Use ES `msearch` (multi-search) to fetch all latest metrics in 1 HTTP request. Use a MongoDB aggregation `$group` pipeline to get all incident counts in 1 query. 100 queries → 2 queries.

**Files**: `dashboard/service.py`

### Expected Impact

| Metric | Before (10 servers) | After (10 servers) | After (100 servers) |
|---|---|---|---|
| Cycle time | 45s | 5s | ~25s |
| ES HTTP requests/cycle | 4000 | ~20 | ~120 |
| MongoDB queries/cycle | 10+ (rules) | 1 (every 5 min) | 1 (every 5 min) |
| Duplicate incidents | Unlimited | Zero | Zero |
| Dashboard queries | 20 | 2 | 2 |

---

## Phase 4 — Performance Optimization Implementation (Mar 29)

After documenting the 6 bottlenecks in the audit above, the next step was actually implementing them. The thought process throughout was: **"what breaks if I add 100 servers?"** — and fixing each answer.

### Thought Process: Why Semaphore Instead of Raw Parallelism

The initial idea was simple: replace `for server in servers: await ...` with `asyncio.gather(*tasks)`. This fires all servers simultaneously. But that creates a new problem:

- 10 servers → 10 SSH connections → fine
- 100 servers → 100 SSH connections → risky (file descriptor exhaustion, memory spikes)
- 1000 servers → 1000 SSH connections → OS rejects them, ES gets overwhelmed, everything times out

The solution was `asyncio.Semaphore(N)` — a concurrency limiter. It works like a checkout counter system: only N servers are processed at any time. When one finishes, the next starts. The limit is configurable via `MAX_CONCURRENT_SERVERS` in `.env` (default: 20).

This means:
- The app scales **linearly** with server count, not exponentially
- Worst case: 1000 servers / 20 at a time = 50 batches × ~5s each = ~250 seconds
- The system never opens more than 20 SSH connections simultaneously, regardless of how many servers exist

### What Changed

#### `app/core/config.py`
- Added `MAX_CONCURRENT_SERVERS: int = 20` setting. Configurable via `.env`.

#### `app/core/scheduler.py` — Full Rewrite
- Created a module-level `_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_SERVERS)`
- Created `_run_with_limit(coro)` helper that wraps any coroutine with the semaphore
- All 4 jobs (`job_log_collection`, `job_metric_collection`, `job_health_check`, `job_file_watcher`) now:
  1. Fetch all servers at once (`find().to_list()`)
  2. Create a task per server, wrapped with `_run_with_limit()`
  3. Fire all tasks via `asyncio.gather(*tasks, return_exceptions=True)`
  4. Log individual server failures without crashing the cycle
- Health check interval changed from 30s to 60s (was unnecessarily aggressive)

#### `app/modules/servers/service.py` — `update_all_server_statuses()`
- Replaced `async for server in cursor: await check(server)` with:
  - Load all servers into memory
  - Create a `check_one(server)` inner function wrapped with semaphore
  - Fire all via `asyncio.gather()`

#### `app/modules/logs/service.py` — Major Rewrite (OPT-2 + OPT-3)

**Bulk Indexing (OPT-2):**
- Deleted `_index_to_es()` (individual document indexing)
- Added `_bulk_index_to_es(log_docs)` using `elasticsearch.helpers.async_bulk()`
- Both `_collect_linux_logs()` and `_collect_windows_logs()` now:
  1. Build a list of all new log documents in memory
  2. Call `_bulk_index_to_es()` once at the end with the full list
  3. Import changed: `from elasticsearch.helpers import async_bulk`

**O(1) Dedup (OPT-3):**
- Deleted `_check_exists_in_es()` (per-log ES search)
- Added `_get_latest_timestamp(server_id)` — queries ES once for the most recent log timestamp for a given server
- In the collection loop, logs with `timestamp <= latest_ts` are skipped using a pure Python ISO string comparison (no network call)
- This changes 200 dedup queries per server per cycle → 1 query

#### `app/modules/analysis/service.py` — OPT-4 + OPT-5

**Rule Cache (OPT-4):**
- Added module-level `_rule_cache` dict with keys: `rules` (list), `loaded_at` (unix timestamp), `ttl` (300 seconds)
- Added `_get_cached_rules()` async function that:
  1. Checks if cache is stale (older than TTL)
  2. If stale: re-fetches from MongoDB, re-compiles regex, updates cache
  3. If fresh: returns cached rules instantly (pure Python, no DB call)
- `analyze_logs()` now calls `_get_cached_rules()` instead of querying MongoDB directly
- OS filtering still happens per-call but using Python list comprehension (no DB)

**Duplicate Incident Prevention (OPT-5):**
- Before creating any incident, the engine now checks:
  ```python
  existing = await db["incidents"].find_one({
      "server_id": ...,
      "rule_id": ...,
      "detected_at": {"$gte": (now - 5 minutes)}
  })
  if existing: continue
  ```
- This prevents the same rule from creating duplicate incidents for the same server within a 5-minute window

#### `app/modules/dashboard/service.py` — OPT-6

**Batch Metrics (OPT-6A):**
- Replaced N individual `es.search()` calls with 1 `es.msearch()` call
- `msearch` sends multiple search requests in a single HTTP body
- Results are mapped back to server IDs using array index alignment

**Batch Incident Counts (OPT-6B):**
- Replaced N individual `count_documents()` calls with 1 MongoDB aggregation pipeline:
  ```python
  [
      {"$match": {"status": {"$in": ["open", "investigating"]}}},
      {"$group": {"_id": "$server_id", "count": {"$sum": 1}}}
  ]
  ```
- Returns all open incident counts grouped by server in one query

**Batch Hostname Lookup (get_recent_incidents):**
- Replaced per-server `find_one()` calls with a single `find({"_id": {"$in": oid_list}})` query
