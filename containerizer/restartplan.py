"""A planned restart of the appliance (Admin -> System): a plain restart, an upgrade or a roll back, now or at
a time an administrator picks. From that time on the scan worker claims no new scan run and the LLM queue
runner starts no new job; the work in progress finishes, and the system agent (sysagent.py, `restart-check`,
every minute) restarts the appliance once nothing runs any more, or when the longest wait the administrator
allowed is over (a scan cut off then is marked failed at the next start, an LLM job goes back to the queue).

The system agent keeps the plan on the persistent partition and publishes it in its world-readable status
(/run/containerizer/system/status.json, key `restart`), which is what the worker and the runner read here.
Outside the appliance there is no status file and nothing is ever held.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

STATUS = Path("/run/containerizer/system/status.json")
ACTIONS = ("reboot", "upgrade", "rollback")
WAITS = (0, 30, 60, 120, 240, 480)      # minutes the form offers; None: until the work is done
DEFAULT_WAIT = 120
MAX_AHEAD = timedelta(days=30)


def status_path() -> Path:
    d = os.environ.get("CONTAINERIZER_SYSTEM_DIR")
    return Path(d) / "status.json" if d else STATUS


def parse_time(v) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def planned(path: Path | None = None) -> dict | None:
    """The plan the system agent published, or None."""
    try:
        st = json.loads((path or status_path()).read_text())
    except (OSError, ValueError):
        return None
    p = st.get("restart") if isinstance(st, dict) else None
    return p if isinstance(p, dict) and p.get("action") in ACTIONS else None


def starts(plan: dict | None) -> datetime | None:
    return parse_time(plan.get("at")) if plan else None


def holding(now: datetime | None = None, path: Path | None = None, llm: bool = False) -> str | None:
    """Why new work must wait (a restart is due), or None. `llm`: the LLM queue runner asks; an app update does not
    hold it (it finishes its jobs on the code it runs and restarts with the new one: sysagent.restart_services)."""
    plan = planned(path)
    at = starts(plan)
    if at is None or (now or datetime.now(timezone.utc)) < at:
        return None
    if llm and plan.get("app_update"):
        return None
    return f"waiting for the planned {describe(plan)}: no new work starts"


def describe(plan: dict) -> str:
    a = plan.get("action")
    if a == "upgrade":
        return f"upgrade to {plan.get('version') or '?'}"
    if a == "rollback":
        return f"roll back to snapshot {plan.get('snapshot')}"
    return "restart"


def wait_text(minutes) -> str:
    if minutes is None:
        return "until the work in progress is done"
    if minutes == 0:
        return "without waiting for the work in progress"
    return (f"for the work in progress, at most {minutes // 60} h" if minutes % 60 == 0 and minutes >= 60
            else f"for the work in progress, at most {minutes} min")


def due(plan: dict, now: datetime, running: int | None) -> tuple[bool, str]:
    """(restart now, why or why not). `running`: scan runs and LLM jobs in progress (None: unknown, the
    database could not be asked: counted as busy until the wait is over)."""
    at = starts(plan)
    if at is None or now < at:
        return False, "scheduled"
    if running == 0:
        return True, "nothing was running any more"
    wait = plan.get("max_wait_minutes")
    if wait is not None and now >= at + timedelta(minutes=int(wait)):
        return True, ("without waiting" if not wait else
                      f"after waiting {int(wait)} min; {'unknown work' if running is None else f'{running} task(s)'} cut off")
    return False, "waiting for the work in progress"
