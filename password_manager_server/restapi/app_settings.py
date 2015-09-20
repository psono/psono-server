from django.conf import settings

from serializers import (
    LoginSerializer as DefaultLoginSerializer,
    VerifyEmailSerializeras as DefaultVerifyEmailSerializer,
    RegisterSerializer as DefaultRegisterSerializer,
    AuthkeyChangeSerializer as DefaultAuthkeyChangeSerializer,
    DatastoreSerializer as DefaultDatastoreSerializer,
    UserPublicKeySerializer as DefaultUserPublicKeySerializer,
    ShareSerializer as DefaultShareSerializer,
    DatastoreOverviewSerializer as DefaultDatastoreOverviewSerializer,
    ShareOverviewSerializer as DefaultShareOverviewSerializer)
from .utils import import_callable


serializers = getattr(settings, 'RESTAPI_AUTH_SERIALIZERS', {})

LoginSerializer = import_callable(
    serializers.get('LOGIN_SERIALIZER', DefaultLoginSerializer)
)


AuthkeyChangeSerializer = import_callable(
    serializers.get(
        'PASSWORD_CHANGE_SERIALIZER',
        DefaultAuthkeyChangeSerializer
    )
)

RegisterSerializer = import_callable(
    serializers.get(
        'REGISTER_SERIALIZER',
        DefaultRegisterSerializer
    )
)


VerifyEmailSerializer = import_callable(
    serializers.get(
        'VERIFY_EMAIL_SERIALIZER',
        DefaultVerifyEmailSerializer
    )
)

DatastoreSerializer = import_callable(
    serializers.get(
        'DATASTORE_SERIALIZER',
        DefaultDatastoreSerializer
    )
)
UserPublicKeySerializer = import_callable(
    serializers.get(
        'USER_PUBLIC_KEY_SERIALIZER',
        DefaultUserPublicKeySerializer
    )
)

ShareSerializer = import_callable(
    serializers.get(
        'SHARE_SERIALIZER',
        DefaultShareSerializer
    )
)

DatastoreOverviewSerializer = import_callable(
    serializers.get(
        'DATASTORE_OVERVIEW_SERIALIZER',
        DefaultDatastoreOverviewSerializer
    )
)
ShareOverviewSerializer = import_callable(
    serializers.get(
        'SHARE_OVERVIEW_SERIALIZER',
        DefaultShareOverviewSerializer
    )
)

EMAIL_VERIFICATION = 'mandatory'
