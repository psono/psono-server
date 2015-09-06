from django.conf import settings

from serializers import (
    UserDetailsSerializer as DefaultUserDetailsSerializer,
    LoginSerializer as DefaultLoginSerializer,
    VerifyEmailSerializeras as DefaultVerifyEmailSerializer,
    RegisterSerializer as DefaultRegisterSerializer,
    AuthkeyChangeSerializer as DefaultAuthkeyChangeSerializer,
    DatastoreSerializer as DefaultDatastoreSerializer,
    ShareSerializer as DefaultShareSerializer,
    DatastoreOverviewSerializer as DefaultDatastoreOverviewSerializer)
from .utils import import_callable


serializers = getattr(settings, 'RESTAPI_AUTH_SERIALIZERS', {})

UserDetailsSerializer = import_callable(
    serializers.get('USER_DETAILS_SERIALIZER', DefaultUserDetailsSerializer)
)

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

EMAIL_VERIFICATION = 'mandatory'
