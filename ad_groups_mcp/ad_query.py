# NOTE: This module is a copy of the canonical version in the ad-group-audit repo.
# When modifying shared logic, update the ad-group-audit version first, then copy here.
# See README.md for the sync process.

"""AD Query Layer — PowerShell subprocess wrappers for AD cmdlets.

This module provides async functions that shell out to PowerShell
and parse JSON results for Active Directory operations.
"""

from __future__ import annotations

import asyncio
import json
import logging

logger = logging.getLogger(__name__)

PS_TIMEOUT_SECONDS = 30


async def run_ps_command(script: str, timeout: float = PS_TIMEOUT_SECONDS) -> dict | list:
    """Execute a PowerShell script and return parsed JSON output.

    Raises RuntimeError on timeout, non-zero exit, or JSON parse failure.
    """
    proc = await asyncio.create_subprocess_exec(
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"PowerShell command timed out after {timeout}s")

    if proc.returncode != 0:
        error_text = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"PowerShell error (exit {proc.returncode}): {error_text}")

    output = stdout.decode("utf-8", errors="replace").strip()
    if not output:
        return {}

    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse PowerShell JSON output: {exc}")


async def test_ad_module() -> bool:
    """Check if the ActiveDirectory PowerShell module is available.

    Returns True if the module is installed, False otherwise.
    """
    script = "Get-Module -ListAvailable -Name ActiveDirectory | ConvertTo-Json"
    try:
        result = await run_ps_command(script)
        # If result is non-empty, the module exists
        return bool(result)
    except RuntimeError:
        return False


async def get_ad_group(identity: str) -> dict:
    """Retrieve a single AD group with all properties.

    Runs ``Get-ADGroup -Identity <identity> -Properties *`` and returns
    the parsed JSON dict.

    Raises RuntimeError when the group is not found or AD is unreachable.
    """
    # Escape single quotes in the identity to prevent injection
    safe_identity = identity.replace("'", "''")
    script = (
        f"Get-ADGroup -Identity '{safe_identity}' -Properties * "
        "| ConvertTo-Json -Depth 3"
    )
    result = await run_ps_command(script)
    if isinstance(result, list):
        # Single-object queries should not return a list, but handle it
        return result[0] if result else {}
    return result


async def search_ad_groups(query: str) -> list[dict]:
    """Search AD groups whose name matches the given query.

    Runs ``Get-ADGroup -Filter {Name -like '*<query>*'}`` with
    Description and ManagedBy properties and returns a list of dicts.

    Always returns a list, even when PowerShell returns a single object.
    """
    safe_query = query.replace("'", "''")
    script = (
        f"Get-ADGroup -Filter {{Name -like '*{safe_query}*'}} "
        "-Properties Description,ManagedBy "
        "| ConvertTo-Json -Depth 3"
    )
    result = await run_ps_command(script)
    # PowerShell returns a single object (dict) when there is exactly one
    # match — normalise to a list.
    if isinstance(result, dict):
        return [result] if result else []
    return result if isinstance(result, list) else []


async def get_all_ad_groups() -> list[dict]:
    """Retrieve every AD group for inventory audit.

    Runs ``Get-ADGroup -Filter * -Properties Description,ManagedBy``
    and returns a list of dicts.

    Always returns a list, even when PowerShell returns a single object.
    """
    script = (
        "Get-ADGroup -Filter * -Properties Description,ManagedBy,extensionAttribute1,extensionAttribute2 "
        "| ConvertTo-Json -Depth 3"
    )
    result = await run_ps_command(script)
    if isinstance(result, dict):
        return [result] if result else []
    return result if isinstance(result, list) else []


async def get_groups_in_ou(search_base: str) -> list[dict]:
    """Retrieve all AD groups within a specific OU.

    Runs ``Get-ADGroup -Filter * -SearchBase <OU> -SearchScope OneLevel``
    and returns a list of dicts.
    """
    safe_base = search_base.replace("'", "''")
    script = (
        f"Get-ADGroup -Filter * -SearchBase '{safe_base}' -SearchScope OneLevel "
        "-Properties Description,ManagedBy,extensionAttribute1,extensionAttribute2 "
        "| ConvertTo-Json -Depth 3"
    )
    result = await run_ps_command(script)
    if isinstance(result, dict):
        return [result] if result else []
    return result if isinstance(result, list) else []


_DEFAULT_ATTR_MAPPING: dict[str, str] = {
    "reviewed_by": "extensionAttribute1",
    "reviewed_date": "extensionAttribute2",
}


async def set_ad_group_review_attrs(
    identity: str,
    reviewer: str,
    review_date: str,
    attr_mapping: dict[str, str] | None = None,
) -> None:
    """Update extensionAttribute1/2 on an AD group via Set-ADGroup.

    Parameters:
        identity: Group SAM name or DN.
        reviewer: Username to write to extensionAttribute1.
        review_date: YYYY-MM-DD string to write to extensionAttribute2.
        attr_mapping: Optional override for attribute names.

    Raises RuntimeError on PowerShell failure.
    """
    mapping = attr_mapping or _DEFAULT_ATTR_MAPPING
    attr1 = mapping.get("reviewed_by", "extensionAttribute1")
    attr2 = mapping.get("reviewed_date", "extensionAttribute2")

    safe_identity = identity.replace("'", "''")
    safe_reviewer = reviewer.replace("'", "''")
    safe_date = review_date.replace("'", "''")

    script = (
        f"Set-ADGroup -Identity '{safe_identity}' "
        f"-Replace @{{'{attr1}'='{safe_reviewer}';'{attr2}'='{safe_date}'}}"
    )
    await run_ps_command(script)
