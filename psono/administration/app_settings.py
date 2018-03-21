from django.conf import settings

import six
from importlib import import_module

from .serializers import (
    UserSerializer as DefaultUserSerializer,
    DeleteSessionSerializer as DefaultDeleteSessionSerializer,
    DeleteUserSerializer as DefaultDeleteUserSerializer,
    UpdateUserSerializer as DefaultUpdateUserSerializer,
    DeleteYubikeySerializer as DefaultDeleteYubikeySerializer,
    DeleteDuoSerializer as DefaultDeleteDuoSerializer,
    DeleteGASerializer as DefaultDeleteGASerializer,
    DeleteGroupSerializer as DefaultDeleteGroupSerializer,
    DeleteMembershipSerializer as DefaultDeleteMembershipSerializer,
    DeleteRecoveryCodeSerializer as DefaultDeleteRecoveryCodeSerializer,
)

def import_callable(path_or_callable):
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        assert isinstance(path_or_callable, six.string_types)
        package, attr = path_or_callable.rsplit('.', 1)
        return getattr(import_module(package), attr)

serializers = getattr(settings, 'ADMIN_SERIALIZERS', {})

UserSerializer = import_callable(
    serializers.get('USER_SERIALIZER', DefaultUserSerializer)
)

DeleteSessionSerializer = import_callable(
    serializers.get('DELETE_SESSION_SERIALIZER', DefaultDeleteSessionSerializer)
)

DeleteUserSerializer = import_callable(
    serializers.get('DELETE_USER_SERIALIZER', DefaultDeleteUserSerializer)
)

UpdateUserSerializer = import_callable(
    serializers.get('UPDATE_USER_SERIALIZER', DefaultUpdateUserSerializer)
)

DeleteYubikeySerializer = import_callable(
    serializers.get('DELETE_YUBIKEY_SERIALIZER', DefaultDeleteYubikeySerializer)
)

DeleteDuoSerializer = import_callable(
    serializers.get('DELETE_DUO_SERIALIZER', DefaultDeleteDuoSerializer)
)

DeleteGASerializer = import_callable(
    serializers.get('DELETE_GA_SERIALIZER', DefaultDeleteGASerializer)
)

DeleteGroupSerializer = import_callable(
    serializers.get('DELETE_GROUP_SERIALIZER', DefaultDeleteGroupSerializer)
)

DeleteMembershipSerializer = import_callable(
    serializers.get('DELETE_MEMBERSHIP_SERIALIZER', DefaultDeleteMembershipSerializer)
)

DeleteRecoveryCodeSerializer = import_callable(
    serializers.get('DELETE_RECOVERY_CODE_SERIALIZER', DefaultDeleteRecoveryCodeSerializer)
)

