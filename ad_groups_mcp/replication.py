"""Replication metadata reader for AD group membership attribute.

Wraps Get-ADReplicationAttributeMetadata to retrieve change-tracking
information for the ``member`` attribute of an AD group object.
"""

from __future__ import annotations

import logging
from datetime import datetime

from ad_groups_mcp.ad_query import run_ps_command
from ad_groups_mcp.models import ReplicationMetadata

logger = logging.getLogger(__name__)


async def get_member_replication_metadata(
    identity: str,
) -> ReplicationMetadata | None:
    """Query replication metadata for the *member* attribute of a group.

    Parameters
    ----------
    identity:
        Group SAM account name or distinguished name.

    Returns
    -------
    ReplicationMetadata | None
        Metadata for the ``member`` attribute, or ``None`` if no
        membership changes have been recorded.
    """
    safe_identity = identity.replace("'", "''")

    script = (
        f"$meta = Get-ADReplicationAttributeMetadata -Object '{safe_identity}' "
        "-Properties member -ErrorAction SilentlyContinue\n"
        "if ($null -eq $meta) {\n"
        "  Write-Output '{}'\n"
        "} else {\n"
        "  $meta | Select-Object "
        "LastOriginatingChangeTime, "
        "LastOriginatingChangeDirectoryServerIdentity, "
        "LastOriginatingChangeUsn, "
        "Version, "
        "@{N='OriginatingChangePrincipal'; E={$_.LastOriginatingChangeDirectoryServerIdentity}} "
        "| ConvertTo-Json -Depth 3 -Compress\n"
        "}\n"
    )

    result = await run_ps_command(script)

    # Empty dict means no metadata found
    if not result or (isinstance(result, dict) and not result):
        return None

    # If result is a list, take the first entry (member attribute)
    if isinstance(result, list):
        if not result:
            return None
        result = result[0]

    change_time_raw = result.get("LastOriginatingChangeTime")
    change_time: datetime | None = None
    if change_time_raw:
        try:
            change_time = datetime.fromisoformat(str(change_time_raw))
        except (ValueError, TypeError):
            change_time = None

    change_dc = result.get("LastOriginatingChangeDirectoryServerIdentity")
    change_principal = result.get("OriginatingChangePrincipal")

    return ReplicationMetadata(
        last_originating_change_time=change_time,
        last_originating_change_dc=str(change_dc) if change_dc else None,
        originating_change_principal=str(change_principal) if change_principal else None,
    )
