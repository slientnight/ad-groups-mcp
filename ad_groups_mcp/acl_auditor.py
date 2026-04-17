"""ACL Auditor — reads nTSecurityDescriptor and evaluates ACEs against an allow-list.

This module provides the ACLAuditor class which audits AD group object
ACLs for risky permissions (GenericAll, WriteDacl, WriteOwner) held by
principals not in a configurable allow-list.

Only read-only cmdlets (Get-ADObject) are used.
"""

from __future__ import annotations

import logging

from ad_groups_mcp.ad_query import run_ps_command
from ad_groups_mcp.models import ACEViolation, ACLAuditResult

logger = logging.getLogger(__name__)

RISKY_PERMISSIONS = {"GenericAll", "WriteDacl", "WriteOwner"}

# PowerShell script template that:
# 1. Retrieves the nTSecurityDescriptor via Get-ADObject (read-only)
# 2. Enumerates the Access property (ACEs)
# 3. Outputs JSON with IdentityReference and ActiveDirectoryRights per ACE
_ACL_PS_SCRIPT = """\
$obj = Get-ADObject -Identity '{identity}' -Properties nTSecurityDescriptor
$acl = $obj.nTSecurityDescriptor
$aces = $acl.Access | ForEach-Object {{
    @{{
        IdentityReference    = $_.IdentityReference.Value
        ActiveDirectoryRights = $_.ActiveDirectoryRights.ToString()
    }}
}}
$aces | ConvertTo-Json -Depth 3
"""


class ACLAuditor:
    """Audits AD group ACLs for risky permissions outside an allow-list."""

    def __init__(self, allow_list: list[str]) -> None:
        self.allow_list = allow_list

    async def audit_group_acl(self, identity: str) -> ACLAuditResult:
        """Read the nTSecurityDescriptor for *identity* and evaluate all ACEs.

        Returns an ``ACLAuditResult`` with ``clean=True`` when no violations
        are found, or a list of ``ACEViolation`` objects otherwise.
        """
        safe_identity = identity.replace("'", "''")
        script = _ACL_PS_SCRIPT.format(identity=safe_identity)

        result = await run_ps_command(script)

        # Normalise: PowerShell returns a single dict when there is one ACE
        if isinstance(result, dict):
            aces = [result] if result else []
        elif isinstance(result, list):
            aces = result
        else:
            aces = []

        violations: list[ACEViolation] = []
        for ace in aces:
            violation = self.evaluate_ace(ace, self.allow_list, group_dn=identity)
            if violation is not None:
                violations.append(violation)

        return ACLAuditResult(
            group_dn=identity,
            clean=len(violations) == 0,
            violations=violations,
        )

    @staticmethod
    def evaluate_ace(
        ace: dict,
        allow_list: list[str],
        group_dn: str = "",
    ) -> ACEViolation | None:
        """Check whether *ace* represents a risky permission held by an unauthorised principal.

        Returns an ``ACEViolation`` if the ACE grants GenericAll, WriteDacl,
        or WriteOwner to a principal **not** in *allow_list*.  Returns
        ``None`` otherwise.
        """
        principal: str = ace.get("IdentityReference", "")
        rights_str: str = ace.get("ActiveDirectoryRights", "")

        # ActiveDirectoryRights may be a comma-separated combination
        rights = {r.strip() for r in rights_str.split(",")}

        risky_found = rights & RISKY_PERMISSIONS
        if not risky_found:
            return None

        # Check if the principal (or its short name) is in the allow-list.
        # Allow-list entries may be bare names like "Domain Admins" while
        # IdentityReference is typically "DOMAIN\\Domain Admins".
        principal_parts = principal.rsplit("\\", 1)
        short_name = principal_parts[-1] if principal_parts else principal

        if principal in allow_list or short_name in allow_list:
            return None

        # Return the first risky permission found for clarity
        permission = sorted(risky_found)[0]
        return ACEViolation(
            principal=principal,
            permission=permission,
            group_dn=group_dn,
        )
