"""
Autonomy policy — resolves which tools the agent gets based on ai_autonomy_level.

Called at the start of every agent run (load_policy step). Always re-reads the
server doc from DB so a level change takes effect on the next run without restart.

Supported levels:
  read_only  → ALL_READ_TOOLS only (agent can investigate but never mutate)
  suggest    → ALL_READ_TOOLS + mutation tools that queue to ai_actions
               (operator approves/rejects each recommendation)
"""
from typing import List

from langchain_core.tools import BaseTool

from app.modules.ai.tools_read import ALL_READ_TOOLS
from app.modules.ai.tools_mutate import (
    make_dismiss_anomaly_tool,
    make_promote_anomaly_tool,
    make_mark_false_positive_tool,
)


def bind_tools_for_server(
    server: dict,
    run_id: str,
    source_type: str = "",
    source_id: str = "",
) -> List[BaseTool]:
    """
    Return the tool list the agent should receive for this server + run.

      read_only → ALL_READ_TOOLS only (no mutations)
      suggest   → ALL_READ_TOOLS + mutation tools that queue to ai_actions
                  (operator approves/rejects each recommendation)

    source_type/source_id are denormalized onto every queued ai_actions row so
    the frontend can show "AI suggestions for this incident/anomaly" without
    scanning payloads. They default to empty strings to keep the function
    callable for callers that don't track a single source (none today, but
    keeps the API forgiving).
    """
    level: str = server.get("ai_autonomy_level", "read_only")

    if level == "read_only":
        return list(ALL_READ_TOOLS)

    server_id = str(server.get("_id", ""))
    mutate = [
        make_dismiss_anomaly_tool(level, run_id, source_type, source_id, server_id),
        make_promote_anomaly_tool(level, run_id, source_type, source_id, server_id),
        make_mark_false_positive_tool(level, run_id, source_type, source_id, server_id),
    ]
    return list(ALL_READ_TOOLS) + [t for t in mutate if t is not None]
