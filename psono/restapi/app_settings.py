from django.conf import settings

from .serializers import (
    LoginSerializer as DefaultLoginSerializer,
    GAVerifySerializer as DefaultGAVerifySerializer,
    DuoVerifySerializer as DefaultDuoVerifySerializer,
    YubikeyOTPVerifySerializer as DefaultYubikeyOTPVerifySerializer,
    ActivateTokenSerializer as DefaultActivateTokenSerializer,
    LogoutSerializer as DefaultLogoutSerializer,
    VerifyEmailSerializeras as DefaultVerifyEmailSerializer,
    RegisterSerializer as DefaultRegisterSerializer,
    UserSearchSerializer as DefaultUserSearchSerializer,
    UserUpdateSerializer as DefaultUserUpdateSerializer,
    UserDeleteSerializer as DefaultUserDeleteSerializer,
    NewGASerializer as DefaultNewGASerializer,
    NewDuoSerializer as DefaultNewDuoSerializer,
    NewYubikeyOTPSerializer as DefaultNewYubikeyOTPSerializer,
    DeleteYubikeySerializer as DefaultDeleteYubikeySerializer,
    DeleteGASerializer as DefaultDeleteGASerializer,
    DeleteDuoSerializer as DefaultDeleteDuoSerializer,
    CreateShareRightSerializer as DefaultCreateShareRightSerializer,
    UpdateShareRightSerializer as DefaultUpdateShareRightSerializer,
    DeleteShareRightSerializer as DefaultDeleteShareRightSerializer,
    CreateRecoverycodeSerializer as DefaultCreateRecoverycodeSerializer,
    EnableNewPasswordSerializer as DefaultEnableNewPasswordSerializer,
    SetNewPasswordSerializer as DefaultSetNewPasswordSerializer,
    CreateShareLinkSerializer as DefaultCreateShareLinkSerializer,
    UpdateShareLinkSerializer as DefaultUpdateShareLinkSerializer,
    DeleteShareLinkSerializer as DefaultDeleteShareLinkSerializer,
    CreateShareSerializer as DefaultCreateShareSerializer,
    UpdateShareSerializer as DefaultUpdateShareSerializer,
    DatastoreOverviewSerializer as DefaultDatastoreOverviewSerializer,
    CreateDatastoreSerializer as DefaultCreateDatastoreSerializer,
    UpdateDatastoreSerializer as DefaultUpdateDatastoreSerializer,
    DeleteDatastoreSerializer as DefaultDeleteDatastoreSerializer,
    DeleteMembershipSerializer as DefaultDeleteMembershipSerializer,
    ShareOverviewSerializer as DefaultShareOverviewSerializer,
    ShareRightAcceptSerializer as DefaultShareRightAcceptSerializer,
    ShareRightDeclineSerializer as DefaultShareRightDeclineSerializer,
    MoveSecretLinkSerializer as DefaultMoveSecretLinkSerializer,
    DeleteSecretLinkSerializer as DefaultDeleteSecretLinkSerializer,
    CreateGroupSerializer as DefaultCreateGroupSerializer,
    ReadGroupRightsSerializer as DefaultReadGroupRightsSerializer,
    CreateSecretSerializer as DefaultCreateSecretSerializer,
    UpdateSecretSerializer as DefaultUpdateSecretSerializer,
    CreateMembershipSerializer as DefaultCreateMembershipSerializer,
    UpdateMembershipSerializer as DefaultUpdateMembershipSerializer,
    UpdateGroupSerializer as DefaultUpdateGroupSerializer,
    DeleteGroupSerializer as DefaultDeleteGroupSerializer,
    MembershipAcceptSerializer as DefaultMembershipAcceptSerializer,
    MembershipDeclineSerializer as DefaultMembershipDeclineSerializer,
)
from .utils import import_callable


serializers = getattr(settings, 'RESTAPI_AUTH_SERIALIZERS', {})

LoginSerializer = import_callable(
    serializers.get('LOGIN_SERIALIZER', DefaultLoginSerializer)
)

GAVerifySerializer = import_callable(
    serializers.get('GA_VERIFY_SERIALIZER', DefaultGAVerifySerializer)
)

DuoVerifySerializer = import_callable(
    serializers.get('DUO_VERIFY_SERIALIZER', DefaultDuoVerifySerializer)
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


UserSearchSerializer = import_callable(
    serializers.get(
        'USER_SEARCH_SERIALIZER',
        DefaultUserSearchSerializer
    )
)

UserUpdateSerializer = import_callable(
    serializers.get(
        'USER_UPDATE_SERIALIZER',
        DefaultUserUpdateSerializer
    )
)

UserDeleteSerializer = import_callable(
    serializers.get(
        'USER_DELETE_SERIALIZER',
        DefaultUserDeleteSerializer
    )
)

NewGASerializer = import_callable(
    serializers.get(
        'NEW_GA_SERIALIZER',
        DefaultNewGASerializer
    )
)

NewDuoSerializer = import_callable(
    serializers.get(
        'NEW_DUO_SERIALIZER',
        DefaultNewDuoSerializer
    )
)

NewYubikeyOTPSerializer = import_callable(
    serializers.get(
        'NEW_YUBIKEY_OTP_SERIALIZER',
        DefaultNewYubikeyOTPSerializer
    )
)

DeleteYubikeySerializer = import_callable(
    serializers.get(
        'DELETE_YUBIKEY_SERIALIZER',
        DefaultDeleteYubikeySerializer
    )
)

DeleteGASerializer = import_callable(
    serializers.get(
        'DELETE_GA_SERIALIZER',
        DefaultDeleteGASerializer
    )
)

DeleteDuoSerializer = import_callable(
    serializers.get(
        'DELETE_DUO_SERIALIZER',
        DefaultDeleteDuoSerializer
    )
)


CreateShareRightSerializer = import_callable(
    serializers.get(
        'CREATE_SHARE_RIGHT_SERIALIZER',
        DefaultCreateShareRightSerializer
    )
)

UpdateShareRightSerializer = import_callable(
    serializers.get(
        'UPDATE_SHARE_RIGHT_SERIALIZER',
        DefaultUpdateShareRightSerializer
    )
)

DeleteShareRightSerializer = import_callable(
    serializers.get(
        'DELETE_SHARE_RIGHT_SERIALIZER',
        DefaultDeleteShareRightSerializer
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
        'ENABLE_NEW_PASSWORD_SERIALIZER',
        DefaultEnableNewPasswordSerializer
    )
)


SetNewPasswordSerializer = import_callable(
    serializers.get(
        'SET_NEW_PASSWORD_SERIALIZER',
        DefaultSetNewPasswordSerializer
    )
)

CreateShareLinkSerializer = import_callable(
    serializers.get(
        'CREATE_SHARE_LINK_SERIALIZER',
        DefaultCreateShareLinkSerializer
    )
)

UpdateShareLinkSerializer = import_callable(
    serializers.get(
        'UPDATE_SHARE_LINK_SERIALIZER',
        DefaultUpdateShareLinkSerializer
    )
)

DeleteShareLinkSerializer = import_callable(
    serializers.get(
        'DELETE_SHARE_LINK_SERIALIZER',
        DefaultDeleteShareLinkSerializer
    )
)


CreateShareSerializer = import_callable(
    serializers.get(
        'CREATE_SHARE_SERIALIZER',
        DefaultCreateShareSerializer
    )
)


UpdateShareSerializer = import_callable(
    serializers.get(
        'UPDATE_SHARE_SERIALIZER',
        DefaultUpdateShareSerializer
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

UpdateDatastoreSerializer = import_callable(
    serializers.get(
        'UPDATE_DATASTORE_SERIALIZER',
        DefaultUpdateDatastoreSerializer
    )
)

DeleteDatastoreSerializer = import_callable(
    serializers.get(
        'DELETE_DATASTORE_SERIALIZER',
        DefaultDeleteDatastoreSerializer
    )
)


DeleteMembershipSerializer = import_callable(
    serializers.get(
        'DELETE_MEMBERSHIP_SERIALIZER',
        DefaultDeleteMembershipSerializer
    )
)

ShareOverviewSerializer = import_callable(
    serializers.get(
        'SHARE_OVERVIEW_SERIALIZER',
        DefaultShareOverviewSerializer
    )
)

ShareRightAcceptSerializer = import_callable(
    serializers.get(
        'SHARE_RIGHT_ACCEPT_SERIALIZER',
        DefaultShareRightAcceptSerializer
    )
)

ShareRightDeclineSerializer = import_callable(
    serializers.get(
        'SHARE_RIGHT_DECLINE_SERIALIZER',
        DefaultShareRightDeclineSerializer
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

CreateGroupSerializer = import_callable(
    serializers.get(
        'CREATE_GROUP_SERIALIZER',
        DefaultCreateGroupSerializer
    )
)

ReadGroupRightsSerializer = import_callable(
    serializers.get(
        'READ_GROUP_RIGHTS_SERIALIZER',
        DefaultReadGroupRightsSerializer
    )
)

CreateSecretSerializer = import_callable(
    serializers.get(
        'CREATE_SECRET_SERIALIZER',
        DefaultCreateSecretSerializer
    )
)

UpdateSecretSerializer = import_callable(
    serializers.get(
        'UPDATE_SECRET_SERIALIZER',
        DefaultUpdateSecretSerializer
    )
)

CreateMembershipSerializer = import_callable(
    serializers.get(
        'CREATE_MEMBERSHIP_SERIALIZER',
        DefaultCreateMembershipSerializer
    )
)

UpdateMembershipSerializer = import_callable(
    serializers.get(
        'CREATE_MEMBERSHIP_SERIALIZER',
        DefaultUpdateMembershipSerializer
    )
)

UpdateGroupSerializer = import_callable(
    serializers.get(
        'UPDATE_GROUP_SERIALIZER',
        DefaultUpdateGroupSerializer
    )
)

DeleteGroupSerializer = import_callable(
    serializers.get(
        'DELETE_GROUP_SERIALIZER',
        DefaultDeleteGroupSerializer
    )
)

MembershipAcceptSerializer = import_callable(
    serializers.get(
        'MEMBERSHIP_ACCEPT_SERIALIZER',
        DefaultMembershipAcceptSerializer
    )
)

MembershipDeclineSerializer = import_callable(
    serializers.get(
        'MEMBERSHIP_DECLINE_SERIALIZER',
        DefaultMembershipDeclineSerializer
    )
)


EMAIL_VERIFICATION = 'mandatory'
