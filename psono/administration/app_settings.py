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
)

def import_callable(path_or_callable):
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        package, attr = path_or_callable.rsplit('.', 1)
        return getattr(import_module(package), attr)

serializers = getattr(settings, 'ADMIN_SERIALIZERS', {})

ReadSessionSerializer = import_callable(
    serializers.get('READ_SESSION_SERIALIZER', DefaultReadSessionSerializer)
)

DeleteSessionSerializer = import_callable(
    serializers.get('DELETE_SESSION_SERIALIZER', DefaultDeleteSessionSerializer)
)

ReadUserSerializer = import_callable(
    serializers.get('READ_USER_SERIALIZER', DefaultReadUserSerializer)
)

DeleteUserSerializer = import_callable(
    serializers.get('DELETE_USER_SERIALIZER', DefaultDeleteUserSerializer)
)

UpdateUserSerializer = import_callable(
    serializers.get('UPDATE_USER_SERIALIZER', DefaultUpdateUserSerializer)
)

CreateUserSerializer = import_callable(
    serializers.get('CREATE_USER_SERIALIZER', DefaultCreateUserSerializer)
)

DeleteYubikeySerializer = import_callable(
    serializers.get('DELETE_YUBIKEY_SERIALIZER', DefaultDeleteYubikeySerializer)
)

DeleteWebAuthnSerializer = import_callable(
    serializers.get('DELETE_WEBAUTHN_SERIALIZER', DefaultDeleteWebAuthnSerializer)
)

DeleteDuoSerializer = import_callable(
    serializers.get('DELETE_DUO_SERIALIZER', DefaultDeleteDuoSerializer)
)

DeleteGASerializer = import_callable(
    serializers.get('DELETE_GA_SERIALIZER', DefaultDeleteGASerializer)
)

UpdateGroupSerializer = import_callable(
    serializers.get('UPDATE_GROUP_SERIALIZER', DefaultUpdateGroupSerializer)
)

DeleteGroupSerializer = import_callable(
    serializers.get('DELETE_GROUP_SERIALIZER', DefaultDeleteGroupSerializer)
)

ReadGroupSerializer = import_callable(
    serializers.get('READ_GROUP_SERIALIZER', DefaultReadGroupSerializer)
)

UpdateMembershipSerializer = import_callable(
    serializers.get('UPDATE_MEMBERSHIP_SERIALIZER', DefaultUpdateMembershipSerializer)
)

DeleteMembershipSerializer = import_callable(
    serializers.get('DELETE_MEMBERSHIP_SERIALIZER', DefaultDeleteMembershipSerializer)
)

DeleteRecoveryCodeSerializer = import_callable(
    serializers.get('DELETE_RECOVERY_CODE_SERIALIZER', DefaultDeleteRecoveryCodeSerializer)
)

DeleteEmergencyCodeSerializer = import_callable(
    serializers.get('DELETE_EMERGENCY_CODE_SERIALIZER', DefaultDeleteEmergencyCodeSerializer)
)

DeleteLinkShareSerializer = import_callable(
    serializers.get('DELETE_LINK_SHARE_SERIALIZER', DefaultDeleteLinkShareSerializer)
)

