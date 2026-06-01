"""
App-wide AI overview — a single-LLM-call executive summary of the whole
platform for the dashboard.

Unlike the per-server overview agent (`server_graph.run_server_overview`), this
is deliberately lightweight: no tools, no suggested commands, no manual
remediation steps. It gathers app-wide aggregates (server status, incidents,
anomalies, automation activity, log volume) and asks the LLM for a quick
narrative the admin can read at a glance.

Streaming mirrors `script_review` / `server_graph`: tokens are emitted on the
`app.ai` WS topic with `source_type="app"`, `source_id="global"` so the
frontend's `useAiAnalysisStream("app", "global", undefined, …, "app.ai")` can
drive the live typing cursor. The final markdown is persisted as an
`ai_analysis` row of type `app_overview` so the dashboard can show the last
result on revisit without re-running the LLM (generation is on-demand only).
"""
from app.core.constants import (
    Collections, WSEvent, AnalysisType,
    NotificationType, NotificationCategory, NotificationSeverity,
)
import json
import uuid
from datetime import timezone

from langchain_core.messages import HumanMessage

from app.core.config import settings
from app.core.database import get_database
from app.core.datetime_utils import utc_now
from app.core.events import event_bus
from app.modules.ai.llm import get_chat_model
from app.modules.ai.analysis_store import save_analysis, list_analyses_for_source
from app.modules.notifications.feed import notify

_TOPIC = "app.ai"
_SOURCE_TYPE = "app"
_SOURCE_ID = "global"


APP_OVERVIEW_SYSTEM_PROMPT = """You are a Senior SecOps engineer writing a concise health & risk overview of an ENTIRE security-monitoring platform for the admin who just opened the dashboard. They want a fast, honest read on the state of the whole fleet — what's healthy, what's degrading, what's worth watching.

# What this platform is
It is an AGENTLESS monitoring system: it connects to a fleet of Linux/Windows servers over SSH/WinRM (nothing is installed on them) and every ~60 seconds collects logs and metrics. The pipeline:
- DETECTION — ~55 regex rules match incoming log lines; a match opens an INCIDENT. Each rule has an action level: L1 auto-remediate silently, L2 auto-remediate and alert, L3 alert only.
- AUTO-REMEDIATION — when a matched rule has a remediation script, the platform runs it, moves the incident to VERIFYING, and auto-resolves it if the fix holds; otherwise it retries up to 3× then escalates. These runs are the "automation"/remediation history.
- TIER-2 HEURISTICS — log lines that match NO rule are scored by heuristics (high-signal keywords, never-seen-before "novel" patterns, off-hours activity) and recorded as ANOMALIES awaiting human triage. An admin then dismisses each as noise or promotes it to an incident.
- ALERTING — qualifying incidents email the admin.

So: INCIDENTS = confirmed rule matches (the system already knows what they are). ANOMALIES = suspicious-but-unclassified signals waiting for a human. AUTOMATION = the auto-fix attempts.

# How to read the JSON snapshot you are given
- `servers`: health counts. `online` = reachable AND credentials work (full visibility). `reachable` = TCP-reachable but the auth probe FAILED — a blind spot, no fresh logs/metrics. `offline` = unreachable. Any non-`online` server is a monitoring gap.
- `incidents.by_status`: `open` = active/unaddressed, `investigating`, `resolved` = auto-fixed and verified, `false_positive`. `by_severity`: critical/high/medium/low. Open critical/high are the priorities.
- `logs`: `total` and `last_24h` lines ingested. `last_24h` near 0 on an otherwise-online fleet can mean ingestion has stalled.
- `rules`: count of ENABLED detection rules. `scripts`: remediation scripts available.
- `anomalies`: the Tier-2 pile. `pending` = un-triaged (a large/growing value is a REVIEW BACKLOG — the team is behind on judging novel activity). `promoted` = escalated to incidents. `dismissed` = ruled noise.
- `automation`: remediation runs. `total`/`success`/`failed` are all-time, `last_24h` is the last day, `success_rate` is the percent that succeeded. A low success_rate or a cluster of recent failures means auto-fix is NOT holding and incidents are likely recurring.
- `recent_open_incidents`: latest still-open incidents (rule, severity, server, when) — name these specifically.
- `top_pending_anomalies`: highest-signal un-triaged anomalies (severity, why flagged, occurrence count, server, sample line) — cite the concrete ones, especially high-severity or high-occurrence.
- `recent_failed_remediations`: recent failed script runs (script, server, error) — name the script/server when flagging automation trouble.
- `degraded_servers`: servers not `online`, with a `reason` where known — name them.
- `generated_at`: when this snapshot was taken; treat it as "now".

# Rules
- This is a SUMMARY ONLY. Do NOT propose shell commands, scripts, or step-by-step remediation. Do NOT output an "action items" or "recommended commands" section. Observations and a light watch-list are fine; concrete commands are NOT.
- Ground EVERY statement in the JSON. Never invent numbers, hostnames, incidents, or anomalies. If the data doesn't say it, don't claim it.
- Prefer specifics: "2 high-severity incidents on web-prod-01 (SSH brute-force, disk-full)" beats "there are some incidents".
- If a section has nothing notable, say so in ONE line rather than padding. An all-quiet platform is a valid, good result — state it plainly and confidently.
- Be calibrated: don't cry wolf over a single low-severity item, and don't bury a genuine critical issue under routine noise.

# Output
Clean markdown in roughly this shape:

## Overview
A 2-3 sentence headline verdict on overall platform health — most important takeaway first.

## Servers
Online vs reachable/offline. Name any server that is not online and why (from `degraded_servers`).

## Incidents
Open vs resolved, how many critical/high, and call out the notable open ones by rule + host.

## Anomalies
Pending vs promoted/dismissed. If the pending pile is non-trivial, name the highest-signal pending anomalies; flag a growing backlog.

## Automation
Remediation success rate and recent activity; name any recently failed remediations and the servers they ran on.

## Watch list
A short bullet list of the things most worth keeping an eye on right now — observations only, no commands.

Keep the whole thing tight — an admin should be able to skim it in under a minute."""


async def gather_app_context() -> dict:
    """Collect app-wide aggregates to feed the LLM. Reuses existing services.

    Beyond raw counts we pull a few *named specifics* — the latest open
    incidents, the top un-triaged anomalies, and recent failed remediations —
    so the model can cite concrete hostnames/rules/scripts instead of only
    quoting totals. Each enrichment is best-effort: a failure degrades to an
    empty list rather than breaking the whole overview.
    """
    from app.modules.dashboard.service import DashboardService
    from app.modules.anomalies.service import AnomaliesService
    from app.modules.automation.service import AutomationService

    db = get_database()
    dashboard = DashboardService()
    anomaly_service = AnomaliesService()
    automation_service = AutomationService()

    summary = await dashboard.get_summary()

    try:
        anomalies = await anomaly_service.stats()
    except Exception:
        anomalies = {"total": 0, "pending": 0, "dismissed": 0, "promoted": 0}

    try:
        automation = await automation_service.get_history_stats()
    except Exception:
        automation = {}

    # Recent still-open incidents (rule + severity + host + when) so the LLM can
    # call out specifics rather than only quoting counts.
    try:
        recent = await dashboard.get_recent_incidents(limit=10)
        recent_open = [
            {
                "rule": i.get("rule_name") or i.get("description"),
                "severity": i.get("severity"),
                "status": i.get("status"),
                "server": i.get("server_hostname"),
                "detected_at": i.get("detected_at"),
            }
            for i in recent
            if i.get("status") in ("open", "investigating")
        ]
    except Exception:
        recent_open = []

    # Highest-signal un-triaged anomalies so the Anomalies section can name the
    # actual pending pile, not just its size.
    try:
        anom_page = await anomaly_service.list(status="pending_review", page_size=8)
        top_pending_anomalies = [
            {
                "severity": a.get("severity"),
                "reasons": a.get("reasons"),
                "occurrences": a.get("occurrence_count"),
                "server": a.get("server_hostname"),
                "sample": (a.get("log_message") or "")[:160],
                "last_seen_at": a.get("last_seen_at"),
            }
            for a in anom_page.get("results", [])
        ]
    except Exception:
        top_pending_anomalies = []

    # Recent failed remediations so the Automation section can point at the
    # scripts/servers that aren't holding.
    try:
        failed_runs = await automation_service.get_history(status="failed", limit=8)
        recent_failed_remediations = [
            {
                "script": r.get("script_name"),
                "server": r.get("server_hostname"),
                "error": (r.get("error") or r.get("output") or "")[:200],
                "executed_at": r.get("executed_at"),
            }
            for r in failed_runs
        ]
    except Exception:
        recent_failed_remediations = []

    # Servers that aren't fully healthy, with the reason where we have one.
    try:
        degraded_docs = await db[Collections.SERVERS].find(
            {"status": {"$ne": "online"}},
            {
                "hostname": 1,
                "status": 1,
                "auth_failure_reason": 1,
                "consecutive_offline_checks": 1,
            },
        ).to_list(length=100)
        degraded = [
            {
                "hostname": s.get("hostname"),
                "status": s.get("status"),
                "reason": s.get("auth_failure_reason"),
                "consecutive_offline_checks": s.get("consecutive_offline_checks"),
            }
            for s in degraded_docs
        ]
    except Exception:
        degraded = []

    return {
        "generated_at": utc_now().isoformat(),
        "servers": summary.get("servers"),
        "incidents": summary.get("incidents"),
        "logs": summary.get("logs"),
        "rules": summary.get("rules"),
        "scripts": summary.get("scripts"),
        "anomalies": anomalies,
        "automation": automation,
        "recent_open_incidents": recent_open,
        "top_pending_anomalies": top_pending_anomalies,
        "recent_failed_remediations": recent_failed_remediations,
        "degraded_servers": degraded,
    }


def _build_user_message(ctx: dict) -> str:
    return (
        "Current platform state (JSON). Write the overview from this data only.\n\n"
        f"```json\n{json.dumps(ctx, indent=2, default=str)}\n```"
    )


def _chunk_text(chunk) -> str:
    """Extract plain text from a LangChain stream chunk (str or content-parts list)."""
    content = getattr(chunk, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        try:
            return "".join(
                p.get("text", "") if isinstance(p, dict) else str(p) for p in content
            )
        except Exception:
            return ""
    return ""


async def run_app_overview() -> dict:
    """
    Generate the app-wide overview, streaming tokens on the `app.ai` topic and
    persisting the final markdown as an `app_overview` ai_analysis row.

    On-demand only — called from `POST /api/dashboard/ai-overview` via
    asyncio.create_task, so it never blocks the request or runs passively.
    """
    run_id = str(uuid.uuid4())[:8]

    def emit_token(token: str) -> None:
        try:
            event_bus.emit(_TOPIC, WSEvent.AI_ANALYSIS_TOKEN, {
                "run_id": run_id,
                "source_type": _SOURCE_TYPE,
                "source_id": _SOURCE_ID,
                "token": token,
            })
        except Exception:
            pass

    try:
        ctx = await gather_app_context()
        user_message = _build_user_message(ctx)
        model = get_chat_model()

        # Empty token flips the frontend stream state into "running".
        emit_token("")

        chunks: list[str] = []
        async for chunk in model.astream([
            {"role": "system", "content": APP_OVERVIEW_SYSTEM_PROMPT},
            HumanMessage(content=user_message),
        ]):
            token_text = _chunk_text(chunk)
            if not token_text:
                continue
            chunks.append(token_text)
            emit_token(token_text)

        markdown = ("".join(chunks)).strip()
        if not markdown:
            raise RuntimeError("LLM produced no output")

        # First non-empty line (minus markdown heading) as the one-liner.
        first_line = next((ln.strip() for ln in markdown.splitlines() if ln.strip()), "")
        summary = first_line.lstrip("# ").strip()[:200] or "Platform overview"

        analysis_id = await save_analysis(
            run_id=run_id,
            analysis_type=AnalysisType.APP_OVERVIEW,
            source_type=_SOURCE_TYPE,
            source_id=_SOURCE_ID,
            server_id="",
            summary=summary,
            markdown=markdown,
            confidence=0.0,
            structured={"context": ctx},
            anchored_at=utc_now().replace(tzinfo=timezone.utc),
            window_minutes=0,
            llm_provider=settings.LLM_PROVIDER,
            llm_model=settings.LLM_MODEL,
        )

        try:
            event_bus.emit(_TOPIC, WSEvent.AI_ANALYSIS_COMPLETE, {
                "run_id": run_id,
                "source_type": _SOURCE_TYPE,
                "source_id": _SOURCE_ID,
                "analysis_id": analysis_id,
            })
        except Exception:
            pass

        await notify(
            type=NotificationType.AI_ANALYSIS_READY,
            category=NotificationCategory.AI,
            severity=NotificationSeverity.SUCCESS,
            title="Platform overview ready",
            body=(summary or "Platform overview complete.")[:160],
            link="/",
            entity_type="app",
            entity_id=_SOURCE_ID,
        )

        return {"status": "ok", "run_id": run_id, "analysis_id": analysis_id}

    except Exception as exc:
        # Log the raw cause server-side with a short ref, but surface only a
        # clean, user-facing message on the stream — mirrors core/errors.http_error
        # so the dashboard card shows plain English, not a Python exception.
        ref = str(uuid.uuid4())[:8]
        print(f"[app_overview] failed run={run_id} [{ref}]: {type(exc).__name__}: {exc}")
        friendly = f"Couldn't generate the platform overview — please try again. (ref: {ref})"
        try:
            event_bus.emit(_TOPIC, WSEvent.AI_ANALYSIS_COMPLETE, {
                "run_id": run_id,
                "source_type": _SOURCE_TYPE,
                "source_id": _SOURCE_ID,
                "error": friendly,
            })
        except Exception:
            pass

        await notify(
            type=NotificationType.AI_ANALYSIS_FAILED,
            category=NotificationCategory.AI,
            severity=NotificationSeverity.ERROR,
            title="Platform overview failed",
            body="Couldn't generate the platform overview. Please try again.",
            link="/",
            entity_type="app",
            entity_id=_SOURCE_ID,
        )
        return {"status": "error", "run_id": run_id, "error": friendly}


async def get_latest_app_overview() -> dict | None:
    """Return the most recent persisted app_overview analysis, or None."""
    rows = await list_analyses_for_source(
        _SOURCE_TYPE, _SOURCE_ID, analysis_type=AnalysisType.APP_OVERVIEW, limit=1
    )
    return rows[0] if rows else None
