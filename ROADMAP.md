# SecOps-Backend — Production Roadmap

## Current State

**Working:**
- Server CRUD & Status Health Checks
- SSH/Linux & WinRM/Windows execution
- Zero-impact Log & Metric collection (ES & MongoDB batching)
- Rule-based detection & 3-level incident response (auto-remediation)
- Email Alerting Pipeline for High/Critical incidents
- Test simulation endpoints for testing detection rules
- Robust parallel scheduler with per-server WinRM concurrency locks

**Completed Milestones (Session 2):**
- ✅ **P2 Performance Optimizations**: Parallel scheduling, ES bulk indexing, O(1) deduplication, rule caching, and N+1 query batching.
- ✅ **P3 Alerting & Notifications**: Pluggable email notifications via async SMTP triggered by analysis engine.

**Not production-ready because:**
- 🔴 **Zero authentication** — anyone can hit any endpoint
- 🔴 **No input sanitization** — command injection possible via `/execute`
- 🟡 **No structured logging** — just `print()` statements for the app backend
- 🟡 **No deployment config** — can't containerize the app itself
- ⚪ **No Frontend Interface** — API only

---

## Production Priority Order

### 🟢 P1 — Frontend (Next.js)

> Operational UI for analysts to monitor and manage. 
> **⚠️ IMPORTANT:** While building the UI, keep future Auth in mind. Use a centralized state/context for the `user` (even if mocked for now) and build the API service layer so an Authorization header can easily be added to all requests later.

| Task | Details | Status |
|---|---|---|
| **1.1 Dashboard Home** | Server count, incident stats, system health | ⏳ |
| **1.2 Server Management** | List, add, remove, metric charts | ⏳ |
| **1.3 Incident Management** | List, filter, resolve, view context | ⏳ |
| **1.4 Log Viewer** | Full-text search powered by ES | ⏳ |
| **1.5 Rule/Script Management** | CRUD for detection rules and scripts | ⏳ |

---

### 🔴 P4 — Security & Authentication (Backend)

> Do this AFTER the frontend is wired up, before exposing the system to external networks.

| Task | Details | Status |
|---|---|---|
| **4.1 User Module** | JWT auth (login/register), bcrypt hashing, refresh tokens | ⏳ |
| **4.2 Role-Based Access** | `admin` (full access), `analyst` (read + manage incidents), `viewer` | ⏳ |
| **4.3 Protect All Routes** | Auth middleware on every router. Public: only `/login`, `/health` | ⏳ |
| **4.4 Command Sanitization** | Whitelist allowed commands OR remove raw `/execute` entirely | ⏳ |

---

### 🟡 P5 — Resilience & Observability

> Production apps need to recover from failures and tell you what happened.

| Task | Details | Status |
|---|---|---|
| **5.1 Structured Logging** | Replace `print()` with Python `logging` (JSON format) | ⏳ |
| **5.2 API Health Endpoint** | `/health` returns status of MongoDB, ES, scheduler | ⏳ |
| **5.3 Remediation Permissions** | Fix sudo issue (e.g. `iptables` requires root/sudo) | ⏳ |
| **5.4 Windows Remediation** | Port Linux remediation scripts to PowerShell | ⏳ |

---

### 🟣 P6 — Deployment & DevOps

> Containerize everything for reproducible deployment.

| Task | Details | Status |
|---|---|---|
| **6.1 Dockerize the App** | `Dockerfile` for the FastAPI backend | ⏳ |
| **6.2 Full Docker Compose** | One `docker-compose up` starts: app + DBs | ⏳ |
| **6.3 Environment Mgmt** | `.env.production` vs `.env.development` | ⏳ |

---

## Summary

```
P1 Frontend    ████████████  ← Next Application Phase
P2 Performance ✅ COMPLETED  ← Scalability achieved
P3 Alerting    ✅ COMPLETED  ← Communication pipeline live
P4 Security    ████████████  ← Do this AFTER Frontend
P5 Resilience  ██████        ← Polish & Stability
P6 Deployment  ██████        ← Shipping
```

## Known Issues

- **Remediation permissions** — auto-fix commands fail without sudo (tracked in P5.3)
- **Windows Remediation Scripts** — currently using Linux `iptables` and `&&` which naturally fails in PowerShell (tracked in P5.4)
