from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AdministrativeCapability:
    code: str
    category: str
    description: str
    tenant_scopeable: bool


_CAPABILITIES = (
    AdministrativeCapability("system.read", "system", "VIEW_SYSTEM_INFORMATION", False),
    AdministrativeCapability(
        "statistics.read", "system", "VIEW_SYSTEM_WIDE_STATISTICS", False
    ),
    AdministrativeCapability(
        "users.read", "users", "VIEW_USERS_AND_USER_DETAILS", True
    ),
    AdministrativeCapability("users.create", "users", "CREATE_USERS", True),
    AdministrativeCapability("users.update", "users", "UPDATE_USERS", True),
    AdministrativeCapability("users.delete", "users", "DELETE_USERS", True),
    AdministrativeCapability(
        "users.sessions.read", "users", "VIEW_USER_SESSIONS", True
    ),
    AdministrativeCapability(
        "users.sessions.delete", "users", "DELETE_USER_SESSIONS", True
    ),
    AdministrativeCapability(
        "users.mfa.delete", "users", "DELETE_USER_MFA_REGISTRATIONS", True
    ),
    AdministrativeCapability(
        "users.recovery.delete",
        "users",
        "DELETE_RECOVERY_AND_EMERGENCY_CODES",
        True,
    ),
    AdministrativeCapability(
        "users.recovery.read", "users", "VIEW_RECOVERY_AND_EMERGENCY_CODES", True
    ),
    AdministrativeCapability(
        "users.link_shares.delete", "users", "DELETE_USER_LINK_SHARES", True
    ),
    AdministrativeCapability(
        "security_reports.read", "users", "VIEW_USER_SECURITY_REPORTS", True
    ),
    AdministrativeCapability(
        "groups.read", "groups", "VIEW_GROUPS_AND_GROUP_DETAILS", True
    ),
    AdministrativeCapability("groups.update", "groups", "UPDATE_GROUPS", True),
    AdministrativeCapability("groups.delete", "groups", "DELETE_GROUPS", True),
    AdministrativeCapability(
        "groups.memberships.manage", "groups", "MANAGE_GROUP_MEMBERSHIPS", True
    ),
    AdministrativeCapability(
        "groups.memberships.read", "groups", "VIEW_GROUP_MEMBERSHIPS", True
    ),
    AdministrativeCapability(
        "groups.shares.manage", "groups", "MANAGE_GROUP_SHARE_RIGHTS", True
    ),
    AdministrativeCapability(
        "fileservers.read", "fileservers", "VIEW_FILESERVER_INFRASTRUCTURE", False
    ),
    AdministrativeCapability(
        "fileservers.manage", "fileservers", "MANAGE_FILESERVER_INFRASTRUCTURE", False
    ),
)

CAPABILITIES = {capability.code: capability for capability in _CAPABILITIES}


def capability_exists(code):
    return code in CAPABILITIES


def capability_is_tenant_scopeable(code):
    capability = CAPABILITIES.get(code)
    return capability is not None and capability.tenant_scopeable


def capabilities_as_dicts():
    return [asdict(capability) for capability in _CAPABILITIES]
