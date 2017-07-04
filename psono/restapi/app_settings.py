from django.conf import settings

from .serializers import (
    LoginSerializer as DefaultLoginSerializer,
    GAVerifySerializer as DefaultGAVerifySerializer,
    YubikeyOTPVerifySerializer as DefaultYubikeyOTPVerifySerializer,
    ActivateTokenSerializer as DefaultActivateTokenSerializer,
    LogoutSerializer as DefaultLogoutSerializer,
    VerifyEmailSerializeras as DefaultVerifyEmailSerializer,
    RegisterSerializer as DefaultRegisterSerializer,
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
    CreateDatastoreSerializer as DefaultCreateDatastoreSerializer,
    SecretOverviewSerializer as DefaultSecretOverviewSerializer,
    ShareOverviewSerializer as DefaultShareOverviewSerializer,
    MoveSecretLinkSerializer as DefaultMoveSecretLinkSerializer,
    DeleteSecretLinkSerializer as DefaultDeleteSecretLinkSerializer,
)
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

LogoutSerializer = import_callable(
    serializers.get('LOGOUT_SERIALIZER', DefaultLogoutSerializer)
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

CreateDatastoreSerializer = import_callable(
    serializers.get(
        'CREATE_DATASTORE_SERIALIZER',
        DefaultCreateDatastoreSerializer
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

MoveSecretLinkSerializer = import_callable(
    serializers.get(
        'MOVE_SECRET_LINK_SERIALIZER',
        DefaultMoveSecretLinkSerializer
    )
)

DeleteSecretLinkSerializer = import_callable(
    serializers.get(
        'DELETE_SECRET_LINK_SERIALIZER',
        DefaultDeleteSecretLinkSerializer
    )
)

EMAIL_VERIFICATION = 'mandatory'
