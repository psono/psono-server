from django.conf import settings

from serializers import (
    LoginSerializer as DefaultLoginSerializer,
    GAVerifySerializer as DefaultGAVerifySerializer,
    YubikeyOTPVerifySerializer as DefaultYubikeyOTPVerifySerializer,
    ActivateTokenSerializer as DefaultActivateTokenSerializer,
    VerifyEmailSerializeras as DefaultVerifyEmailSerializer,
    RegisterSerializer as DefaultRegisterSerializer,
    DatastoreSerializer as DefaultDatastoreSerializer,
    SecretSerializer as DefaultSecretSerializer,
    UserPublicKeySerializer as DefaultUserPublicKeySerializer,
    UserUpdateSerializer as DefaultUserUpdateSerializer,
    NewGASerializer as DefaultNewGASerializer,
    NewYubikeyOTPSerializer as DefaultNewYubikeyOTPSerializer,
    CreateUserShareRightSerializer as DefaultCreateUserShareRightSerializer,
    UpdateUserShareRightSerializer as DefaultUpdateUserShareRightSerializer,
    CreateRecoverycodeSerializer as DefaultCreateRecoverycodeSerializer,
    EnableNewPasswordSerializer as DefaultEnableNewPasswordSerializer,
    SetNewPasswordSerializer as DefaultSetNewPasswordSerializer,
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

GAVerifySerializer = import_callable(
    serializers.get('GA_VERIFY_SERIALIZER', DefaultGAVerifySerializer)
)

YubikeyOTPVerifySerializer = import_callable(
    serializers.get('YUBIKEY_OTP_VERIFY_SERIALIZER', DefaultYubikeyOTPVerifySerializer)
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

NewGASerializer = import_callable(
    serializers.get(
        'NEW_GA_SERIALIZER',
        DefaultNewGASerializer
    )
)

NewYubikeyOTPSerializer = import_callable(
    serializers.get(
        'NEW_YUBIKEY_OTP_SERIALIZER',
        DefaultNewYubikeyOTPSerializer
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


CreateRecoverycodeSerializer = import_callable(
    serializers.get(
        'CREATE_RECOVERYCODE_SERIALIZER',
        DefaultCreateRecoverycodeSerializer
    )
)


EnableNewPasswordSerializer = import_callable(
    serializers.get(
        'PASSWORD_SERIALIZER',
        DefaultEnableNewPasswordSerializer
    )
)


SetNewPasswordSerializer = import_callable(
    serializers.get(
        'PASSWORD_SERIALIZER',
        DefaultSetNewPasswordSerializer
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
