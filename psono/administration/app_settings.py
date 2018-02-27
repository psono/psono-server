from django.conf import settings

import six
from importlib import import_module

from .serializers import (
    UserSerializer as DefaultUserSerializer,
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

