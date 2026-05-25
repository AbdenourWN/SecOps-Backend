from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime
from enum import Enum
from app.core.datetime_utils import utc_now

class ScriptLanguage(str, Enum):
    BASH = "bash"
    POWERSHELL = "powershell"
    PYTHON = "python"

class ScriptBase(BaseModel):
    name: str = Field(..., description="e.g., 'Restart Nginx'")
    description: Optional[str] = None
    language: ScriptLanguage = ScriptLanguage.BASH
    content: str = Field(..., description="The actual code to execute")
    target_os: Optional[str] = "linux"
    category: Optional[str] = "recovery"   # diagnostic | containment | recovery
    enabled: bool = True                    # disabled scripts degrade rule to alert-only

    # Phase 28.5 — per-server library scoping
    owner_type: Literal["global", "server"] = "global"
    owner_id: Optional[str] = None

class ScriptCreate(ScriptBase):
    pass

class ScriptInDB(ScriptBase):
    id: str = Field(alias="_id")
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    class Config:
        populate_by_name = True

# For the Audit Trail (History of actions taken)
class AutomationLog(BaseModel):
    incident_id: str
    script_id: str
    server_id: str
    executed_at: datetime = Field(default_factory=utc_now)
    status: str # success, failed
    output: Optional[str] = None
    error: Optional[str] = None
    # Phase 28.4 — denormalised AI review verdict + pointer to the full ai_analysis row.
    # All three Optional so legacy rows render as "no review available" in the UI.
    ai_review_id: Optional[str] = None              # → ai_analysis._id once the review completes
    ai_review_verdict: Optional[str] = None         # resolved | partial | no_effect | made_worse | review_failed
    ai_review_summary: Optional[str] = None         # short one-liner (denormalised structured.summary_one_line)
    # Phase 28.5.2 — denormalised copy of the manual checklist when an
    # operator approved a `suggest_manual_remediation` action on this run.
    # Canonical store is on the incident; this is a UX-side cache so the
    # /automation/history/{id} page can render the checklist inline.
    ai_remediation_manual_commands: Optional[list] = None
    ai_remediation_manual_commands_meta: Optional[dict] = None