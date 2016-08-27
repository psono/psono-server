from django.conf import settings

from serializers import (
    LoginSerializer as DefaultLoginSerializer,
    ActivateTokenSerializer as DefaultActivateTokenSerializer,
    VerifyEmailSerializeras as DefaultVerifyEmailSerializer,
    RegisterSerializer as DefaultRegisterSerializer,
    DatastoreSerializer as DefaultDatastoreSerializer,
    SecretSerializer as DefaultSecretSerializer,
    UserPublicKeySerializer as DefaultUserPublicKeySerializer,
    UserUpdateSerializer as DefaultUserUpdateSerializer,
    CreateUserShareRightSerializer as DefaultCreateUserShareRightSerializer,
    UpdateUserShareRightSerializer as DefaultUpdateUserShareRightSerializer,
    ShareTreeSerializer as DefaultShareTreeSerializer,
    CreateShareSerializer as DefaultCreateShareSerializer,
    DatastoreOverviewSerializer as DefaultDatastoreOverviewSerializer,
    SecretOverviewSerializer as DefaultSecretOverviewSerializer,
    ShareOverviewSerializer as DefaultShareOverviewSerializer)
from .utils import import_callable


serializers = getattr(settings, 'RESTAPI_AUTH_SERIALIZERS', {})

LoginSerializer = import_callable(
    serializers.get('LOGIN_SERIALIZER', DefaultLoginSerializer)
)

ActivateTokenSerializer = import_callable(
    serializers.get('ACTIVATE_TOKEN_SERIALIZER', DefaultActivateTokenSerializer)
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

SecretSerializer = import_callable(
    serializers.get(
        'SECRET_SERIALIZER',
        DefaultSecretSerializer
    )
)


UserPublicKeySerializer = import_callable(
    serializers.get(
        'USER_PUBLIC_KEY_SERIALIZER',
        DefaultUserPublicKeySerializer
    )
)

UserUpdateSerializer = import_callable(
    serializers.get(
        'USER_UPDATE_SERIALIZER',
        DefaultUserUpdateSerializer
    )
)


CreateUserShareRightSerializer = import_callable(
    serializers.get(
        'CREATE_SHARE_RIGHT_SERIALIZER',
        DefaultCreateUserShareRightSerializer
    )
)

UpdateUserShareRightSerializer = import_callable(
    serializers.get(
        'UPDATE_SHARE_RIGHT_SERIALIZER',
        DefaultUpdateUserShareRightSerializer
    )
)

ShareTreeSerializer = import_callable(
    serializers.get(
        'SHARE_RIGHT_INHERIT_SERIALIZER',
        DefaultShareTreeSerializer
    )
)


CreateShareSerializer = import_callable(
    serializers.get(
        'CREATE_SHARE_SERIALIZER',
        DefaultCreateShareSerializer
    )
)

DatastoreOverviewSerializer = import_callable(
    serializers.get(
        'DATASTORE_OVERVIEW_SERIALIZER',
        DefaultDatastoreOverviewSerializer
    )
)

SecretOverviewSerializer = import_callable(
    serializers.get(
        'SECRET_OVERVIEW_SERIALIZER',
        DefaultSecretOverviewSerializer
    )
)

ShareOverviewSerializer = import_callable(
    serializers.get(
        'SHARE_OVERVIEW_SERIALIZER',
        DefaultShareOverviewSerializer
    )
)

EMAIL_VERIFICATION = 'mandatory'
