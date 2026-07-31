from django.conf import settings

from importlib import import_module

from .serializers import (
    ReadSessionSerializer as DefaultReadSessionSerializer,
    DeleteSessionSerializer as DefaultDeleteSessionSerializer,
    ReadUserSerializer as DefaultReadUserSerializer,
    DeleteUserSerializer as DefaultDeleteUserSerializer,
    UpdateUserSerializer as DefaultUpdateUserSerializer,
    CreateUserSerializer as DefaultCreateUserSerializer,
    DeleteYubikeySerializer as DefaultDeleteYubikeySerializer,
    DeleteWebAuthnSerializer as DefaultDeleteWebAuthnSerializer,
    DeleteDuoSerializer as DefaultDeleteDuoSerializer,
    DeleteGASerializer as DefaultDeleteGASerializer,
    UpdateGroupSerializer as DefaultUpdateGroupSerializer,
    DeleteGroupSerializer as DefaultDeleteGroupSerializer,
    ReadGroupSerializer as DefaultReadGroupSerializer,
    UpdateMembershipSerializer as DefaultUpdateMembershipSerializer,
    DeleteMembershipSerializer as DefaultDeleteMembershipSerializer,
    DeleteRecoveryCodeSerializer as DefaultDeleteRecoveryCodeSerializer,
    DeleteEmergencyCodeSerializer as DefaultDeleteEmergencyCodeSerializer,
    DeleteLinkShareSerializer as DefaultDeleteLinkShareSerializer,
    UpdateGroupShareRightSerializer as DefaultUpdateGroupShareRightSerializer,
    DeleteGroupShareRightSerializer as DefaultDeleteGroupShareRightSerializer,
    ReadSecurityReportSerializer as DefaultReadSecurityReportSerializer,
    DeleteIvaltSerializer as DefaultDeleteIvaltSerializer,
    CreateFileserverClusterSerializer as DefaultCreateFileserverClusterSerializer,
    CreateFileserverClusterShardLinkSerializer as DefaultCreateFileserverClusterShardLinkSerializer,
    CreateFileserverShardSerializer as DefaultCreateFileserverShardSerializer,
    DeleteFileserverClusterSerializer as DefaultDeleteFileserverClusterSerializer,
    DeleteFileserverClusterShardLinkSerializer as DefaultDeleteFileserverClusterShardLinkSerializer,
    DeleteFileserverShardSerializer as DefaultDeleteFileserverShardSerializer,
    GenerateFileserverClusterConfigSerializer as DefaultGenerateFileserverClusterConfigSerializer,
    ReadFileserverClusterSerializer as DefaultReadFileserverClusterSerializer,
    ReadFileserverSerializer as DefaultReadFileserverSerializer,
    ReadFileserverShardSerializer as DefaultReadFileserverShardSerializer,
    UpdateFileserverClusterSerializer as DefaultUpdateFileserverClusterSerializer,
    UpdateFileserverClusterShardLinkSerializer as DefaultUpdateFileserverClusterShardLinkSerializer,
    UpdateFileserverShardSerializer as DefaultUpdateFileserverShardSerializer,
)


def import_callable(path_or_callable):
    if hasattr(path_or_callable, "__call__"):
        return path_or_callable
    else:
        package, attr = path_or_callable.rsplit(".", 1)
        return getattr(import_module(package), attr)


serializers = getattr(settings, "ADMIN_SERIALIZERS", {})

ReadSessionSerializer = import_callable(
    serializers.get("READ_SESSION_SERIALIZER", DefaultReadSessionSerializer)
)

DeleteSessionSerializer = import_callable(
    serializers.get("DELETE_SESSION_SERIALIZER", DefaultDeleteSessionSerializer)
)

ReadUserSerializer = import_callable(
    serializers.get("READ_USER_SERIALIZER", DefaultReadUserSerializer)
)

DeleteUserSerializer = import_callable(
    serializers.get("DELETE_USER_SERIALIZER", DefaultDeleteUserSerializer)
)

UpdateUserSerializer = import_callable(
    serializers.get("UPDATE_USER_SERIALIZER", DefaultUpdateUserSerializer)
)

CreateUserSerializer = import_callable(
    serializers.get("CREATE_USER_SERIALIZER", DefaultCreateUserSerializer)
)

DeleteYubikeySerializer = import_callable(
    serializers.get("DELETE_YUBIKEY_SERIALIZER", DefaultDeleteYubikeySerializer)
)

DeleteWebAuthnSerializer = import_callable(
    serializers.get("DELETE_WEBAUTHN_SERIALIZER", DefaultDeleteWebAuthnSerializer)
)

DeleteDuoSerializer = import_callable(
    serializers.get("DELETE_DUO_SERIALIZER", DefaultDeleteDuoSerializer)
)

DeleteGASerializer = import_callable(
    serializers.get("DELETE_GA_SERIALIZER", DefaultDeleteGASerializer)
)

UpdateGroupSerializer = import_callable(
    serializers.get("UPDATE_GROUP_SERIALIZER", DefaultUpdateGroupSerializer)
)

DeleteGroupSerializer = import_callable(
    serializers.get("DELETE_GROUP_SERIALIZER", DefaultDeleteGroupSerializer)
)

ReadGroupSerializer = import_callable(
    serializers.get("READ_GROUP_SERIALIZER", DefaultReadGroupSerializer)
)

UpdateMembershipSerializer = import_callable(
    serializers.get("UPDATE_MEMBERSHIP_SERIALIZER", DefaultUpdateMembershipSerializer)
)

DeleteMembershipSerializer = import_callable(
    serializers.get("DELETE_MEMBERSHIP_SERIALIZER", DefaultDeleteMembershipSerializer)
)

DeleteRecoveryCodeSerializer = import_callable(
    serializers.get(
        "DELETE_RECOVERY_CODE_SERIALIZER", DefaultDeleteRecoveryCodeSerializer
    )
)

DeleteEmergencyCodeSerializer = import_callable(
    serializers.get(
        "DELETE_EMERGENCY_CODE_SERIALIZER", DefaultDeleteEmergencyCodeSerializer
    )
)

DeleteLinkShareSerializer = import_callable(
    serializers.get("DELETE_LINK_SHARE_SERIALIZER", DefaultDeleteLinkShareSerializer)
)

UpdateGroupShareRightSerializer = import_callable(
    serializers.get(
        "UPDATE_GROUP_SHARE_RIGHT_SERIALIZER", DefaultUpdateGroupShareRightSerializer
    )
)

DeleteGroupShareRightSerializer = import_callable(
    serializers.get(
        "DELETE_GROUP_SHARE_RIGHT_SERIALIZER", DefaultDeleteGroupShareRightSerializer
    )
)

ReadSecurityReportSerializer = import_callable(
    serializers.get(
        "READ_SECURITY_REPORT_SERIALIZER", DefaultReadSecurityReportSerializer
    )
)

DeleteIvaltSerializer = import_callable(
    serializers.get("DELETE_IVALT_SERIALIZER", DefaultDeleteIvaltSerializer)
)

ReadFileserverClusterSerializer = import_callable(
    serializers.get(
        "READ_FILESERVER_CLUSTER_SERIALIZER", DefaultReadFileserverClusterSerializer
    )
)
CreateFileserverClusterSerializer = import_callable(
    serializers.get(
        "CREATE_FILESERVER_CLUSTER_SERIALIZER",
        DefaultCreateFileserverClusterSerializer,
    )
)
UpdateFileserverClusterSerializer = import_callable(
    serializers.get(
        "UPDATE_FILESERVER_CLUSTER_SERIALIZER",
        DefaultUpdateFileserverClusterSerializer,
    )
)
DeleteFileserverClusterSerializer = import_callable(
    serializers.get(
        "DELETE_FILESERVER_CLUSTER_SERIALIZER",
        DefaultDeleteFileserverClusterSerializer,
    )
)
ReadFileserverShardSerializer = import_callable(
    serializers.get(
        "READ_FILESERVER_SHARD_SERIALIZER", DefaultReadFileserverShardSerializer
    )
)
CreateFileserverShardSerializer = import_callable(
    serializers.get(
        "CREATE_FILESERVER_SHARD_SERIALIZER", DefaultCreateFileserverShardSerializer
    )
)
UpdateFileserverShardSerializer = import_callable(
    serializers.get(
        "UPDATE_FILESERVER_SHARD_SERIALIZER", DefaultUpdateFileserverShardSerializer
    )
)
DeleteFileserverShardSerializer = import_callable(
    serializers.get(
        "DELETE_FILESERVER_SHARD_SERIALIZER", DefaultDeleteFileserverShardSerializer
    )
)
CreateFileserverClusterShardLinkSerializer = import_callable(
    serializers.get(
        "CREATE_FILESERVER_CLUSTER_SHARD_LINK_SERIALIZER",
        DefaultCreateFileserverClusterShardLinkSerializer,
    )
)
UpdateFileserverClusterShardLinkSerializer = import_callable(
    serializers.get(
        "UPDATE_FILESERVER_CLUSTER_SHARD_LINK_SERIALIZER",
        DefaultUpdateFileserverClusterShardLinkSerializer,
    )
)
DeleteFileserverClusterShardLinkSerializer = import_callable(
    serializers.get(
        "DELETE_FILESERVER_CLUSTER_SHARD_LINK_SERIALIZER",
        DefaultDeleteFileserverClusterShardLinkSerializer,
    )
)
ReadFileserverSerializer = import_callable(
    serializers.get("READ_FILESERVER_SERIALIZER", DefaultReadFileserverSerializer)
)
GenerateFileserverClusterConfigSerializer = import_callable(
    serializers.get(
        "GENERATE_FILESERVER_CLUSTER_CONFIG_SERIALIZER",
        DefaultGenerateFileserverClusterConfigSerializer,
    )
)
