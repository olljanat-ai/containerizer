"""Organization-wide values the generator uses for every application.

`timezone`: the IANA time zone the old servers ran in. Read from, first that is set:
CONTAINERIZER_TIMEZONE (the appliance's worker sets it from Admin -> Source control & LLM -> Site), site.yaml in
your own internal rules repository (CONTAINERIZER_REVIEWED_RULES), rules/site.yaml. Empty: UTC.
"""
from __future__ import annotations

import os
import re

import yaml

from .rules import RULES_DIR, reviewed_dir

TIMEZONE_ENV = "CONTAINERIZER_TIMEZONE"
# an IANA zone name (Europe/Helsinki, America/Argentina/Buenos_Aires, Etc/GMT-2, UTC): what tzdata has a file for
_TZ = re.compile(r"[A-Za-z][A-Za-z0-9_+-]{0,40}(/[A-Za-z0-9_+-]{1,40}){0,2}")


class SiteError(ValueError):
    pass


def valid_timezone(tz: str) -> str:
    """The zone name, stripped; "" for none. Raises SiteError for what is not an IANA zone name."""
    tz = (tz or "").strip()
    if not tz:
        return ""
    if not _TZ.fullmatch(tz) or ".." in tz:
        raise SiteError(f"timezone {tz!r}: give an IANA time zone such as Europe/Helsinki")
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            ZoneInfo(tz)
        except ZoneInfoNotFoundError:
            # Windows ids ("FLE Standard Time") and typos; a host without tzdata cannot tell, so only a known miss counts
            from zoneinfo import available_timezones
            if available_timezones():
                raise SiteError(f"timezone {tz!r}: not an IANA time zone (Europe/Helsinki, America/New_York)") from None
    except ImportError:
        pass
    return tz


def _from_file(d) -> str | None:
    if not d:
        return None
    p = d / "site.yaml"
    if not p.is_file():
        return None
    data = yaml.safe_load(p.read_text()) or {}
    v = data.get("timezone") if isinstance(data, dict) else None
    return None if v is None else str(v)


def timezone(env=None) -> str:
    """The organization's time zone, "" for UTC."""
    env = os.environ if env is None else env
    v = env.get(TIMEZONE_ENV)
    if v is None or not v.strip():
        v = _from_file(reviewed_dir())
    if v is None or not v.strip():
        v = _from_file(RULES_DIR) or ""
    return valid_timezone(v)
