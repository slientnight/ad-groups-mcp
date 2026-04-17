"""Security event log query for AD group membership changes.

Queries the Windows Security event log via Get-WinEvent for
security-group-management events (Event IDs 4728, 4729, 4732,
4733, 4756, 4757).
"""

from __future__ import annotations

import logging
from datetime import datetime

from ad_groups_mcp.ad_query import run_ps_command
from ad_groups_mcp.models import SecurityEvent

logger = logging.getLogger(__name__)

# Event IDs for security-group-management changes
_GROUP_CHANGE_EVENT_IDS = (4728, 4729, 4732, 4733, 4756, 4757)


async def get_group_change_events(
    identity: str,
    start_time: str | None = None,
    end_time: str | None = None,
) -> list[SecurityEvent]:
    """Query Windows Security log for group membership change events.

    Parameters
    ----------
    identity:
        Group SAM account name or distinguished name to filter on.
    start_time:
        Optional ISO-8601 start bound (inclusive).
    end_time:
        Optional ISO-8601 end bound (inclusive).

    Returns
    -------
    list[SecurityEvent]
        Matching events sorted by timestamp descending.

    Raises
    ------
    RuntimeError
        If the Security event log is unavailable or cannot be read.
    """
    id_csv = ",".join(str(eid) for eid in _GROUP_CHANGE_EVENT_IDS)

    # Build the XPath filter for Get-WinEvent
    time_filters: list[str] = []
    if start_time is not None:
        time_filters.append(
            f"TimeCreated[@SystemTime>='{start_time}']"
        )
    if end_time is not None:
        time_filters.append(
            f"TimeCreated[@SystemTime<='{end_time}']"
        )

    time_clause = ""
    if time_filters:
        time_clause = " and " + " and ".join(time_filters)

    xpath_filter = (
        f"*[System[(EventID={id_csv}){time_clause}]]"
    )

    safe_identity = identity.replace("'", "''")

    script = (
        "$events = @()\n"
        "try {\n"
        f"  $raw = Get-WinEvent -LogName Security -FilterXPath '{xpath_filter}' -ErrorAction Stop\n"
        "  foreach ($evt in $raw) {\n"
        "    $xml = [xml]$evt.ToXml()\n"
        "    $data = $xml.Event.EventData.Data\n"
        "    $targetGroup = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'\n"
        f"    if ($targetGroup -like '*{safe_identity}*') {{\n"
        "      $events += @{\n"
        "        EventId     = $evt.Id\n"
        "        Timestamp   = $evt.TimeCreated.ToString('o')\n"
        "        Account     = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'\n"
        "        Member      = ($data | Where-Object { $_.Name -eq 'MemberName' }).'#text'\n"
        "        TargetGroup = $targetGroup\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "} catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {\n"
        "  throw 'Security event log is unavailable on this host'\n"
        "} catch [System.UnauthorizedAccessException] {\n"
        "  throw 'Access denied reading Security event log — check audit policy and permissions'\n"
        "}\n"
        "if ($events.Count -eq 0) { ConvertTo-Json @() -Compress }\n"
        "else { $events | ConvertTo-Json -Depth 3 -Compress }\n"
    )

    try:
        result = run_ps_command(script)
        # run_ps_command is async
        if hasattr(result, "__await__"):
            result = await result
    except RuntimeError as exc:
        msg = str(exc)
        if "unavailable" in msg.lower() or "access denied" in msg.lower():
            raise RuntimeError(
                "Security event log is unavailable or access is denied. "
                "Ensure the Windows Security log exists and audit policy is configured."
            ) from exc
        raise

    # Normalise to list
    if isinstance(result, dict):
        raw_events = [result] if result else []
    elif isinstance(result, list):
        raw_events = result
    else:
        raw_events = []

    events: list[SecurityEvent] = []
    for item in raw_events:
        events.append(
            SecurityEvent(
                event_id=int(item.get("EventId", 0)),
                timestamp=datetime.fromisoformat(
                    str(item.get("Timestamp", ""))
                ),
                account=str(item.get("Account", "")),
                member=str(item.get("Member", "")),
                target_group=str(item.get("TargetGroup", "")),
            )
        )

    return events
