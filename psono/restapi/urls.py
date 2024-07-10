"""psono URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  re_path(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  re_path(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  re_path(r'^blog/', include(blog_urls))
"""
from django.urls import re_path
from django.conf import settings
from os.path import join, dirname, abspath
import django
from . import views

urlpatterns = [
    # URLs that do not require a session or valid token
    #re_path(r'^authentication/authkey/reset/$', views.AuthkeyResetView.as_view(),
    #    name='authentication_authkey_reset'),
    #re_path(r'^authentication/authkey/reset/confirm/$', views.AuthkeyResetConfirmView.as_view(),
    #    name='authentication_authkey_reset_confirm'),
    re_path(r'^authentication/prelogin/$', views.PreLoginView.as_view(), name='authentication_prelogin'),
    re_path(r'^authentication/login/$', views.LoginView.as_view(), name='authentication_login'),
    re_path(r'^authentication/logout/$', views.LogoutView.as_view(), name='authentication_logout'),
    re_path(r'^authentication/ga-verify/$', views.GAVerifyView.as_view(), name='authentication_ga_verify'),
    re_path(r'^authentication/duo-verify/$', views.DuoVerifyView.as_view(), name='authentication_duo_verify'),
    re_path(r'^authentication/webauthn-verify/$', views.WebauthnVerifyView.as_view(), name='authentication_webauthn_verify'),
    re_path(r'^authentication/yubikey-otp-verify/$', views.YubikeyOTPVerifyView.as_view(), name='authentication_yubikey_otp_verify'),
    re_path(r'^authentication/ivalt-verify/$', views.IvaltVerifyView.as_view(), name='authentication_ivalt_verify'),
    re_path(r'^authentication/activate-token/$', views.ActivateTokenView.as_view(), name='authentication_activate_token'),
    re_path(r'^authentication/sessions/$', views.SessionView.as_view(), name='authentication_session'),

    re_path(r'^authentication/register/$', views.RegisterView.as_view(), name='authentication_register'),
    re_path(r'^authentication/verify-email/$', views.VerifyEmailView.as_view(), name='authentication_verify_email'),

    re_path(r'^user/update/$', views.UserUpdate.as_view(), name='user_update'),
    re_path(r'^user/ga/$', views.UserGA.as_view(), name='user_ga'),
    re_path(r'^user/duo/$', views.UserDuo.as_view(), name='user_duo'),
    re_path(r'^user/webauthn/$', views.UserWebauthn.as_view(), name='user_webauthn'),
    re_path(r'^user/yubikey-otp/$', views.UserYubikeyOTP.as_view(), name='user_yubikey_otp'),
    re_path(r'^user/ivalt/$', views.UserIvalt.as_view(), name='user_ivalt'),
    re_path(r'^user/search/$', views.UserSearch.as_view(), name='user_search'),
    re_path(r'^user/policy/$', views.UserPolicyView.as_view(), name='user_policy'),
    re_path(r'^user/delete/$', views.UserDelete.as_view(), name='user_delete'),
    re_path(r'^user/security-report/$', views.SecurityReportView.as_view(), name='user_security_report'),

    re_path(r'^user/status/$', views.StatusView.as_view(), name='user_status'),

    re_path(r'^avatar-image/(?P<user_id>[^/]+)/(?P<avatar_id>[^/]+)/$', views.AvatarImageView.as_view(), name='avatar_image'),
    re_path(r'^avatar/$', views.AvatarView.as_view(), name='avatar'),
    re_path(r'^password/$', views.PasswordView.as_view(), name='password'),
    re_path(r'^recoverycode/$', views.RecoveryCodeView.as_view(), name='recoverycode'),

    re_path(r'^emergencycode/$', views.EmergencyCodeView.as_view(), name='emergencycode'),
    re_path(r'^emergency-login/$', views.EmergencyLoginView.as_view(), name='emergency_login'),

    re_path(r'^api-key-access/inspect/$', views.APIKeyAccessInspectView.as_view(), name='api_key_access_inspect'),
    re_path(r'^api-key-access/secret/$', views.APIKeyAccessSecretView.as_view(), name='api_key_access_secret'),

    re_path(r'^api-key/secret/(?P<api_key_id>[^/]+)/$', views.APIKeySecretView.as_view(), name='api_key_secret'),
    re_path(r'^api-key/secret/$', views.APIKeySecretView.as_view(), name='api_key_secret'),
    re_path(r'^api-key/login/$', views.APIKeyLoginView.as_view(), name='api_key_login'),
    re_path(r'^api-key/(?P<api_key_id>[^/]+)/$', views.APIKeyView.as_view(), name='api_key'),
    re_path(r'^api-key/$', views.APIKeyView.as_view(), name='api_key'),

    re_path(r'^link-share-access/$', views.LinkShareAccessView.as_view(), name='link_share_access'),
    re_path(r'^link-share/(?P<link_share_id>[^/]+)/$', views.LinkShareView.as_view(), name='link_share'),
    re_path(r'^link-share/$', views.LinkShareView.as_view(), name='link_share'),

    re_path(r'^datastore/$', views.DatastoreView.as_view(), name='datastore'),
    re_path(r'^datastore/(?P<datastore_id>[^/]+)/$', views.DatastoreView.as_view(), name='datastore'),

    re_path(r'^file/link/$', views.FileLinkView.as_view(), name='file_link'),

    re_path(r'^file/$', views.FileView.as_view(), name='file'),
    re_path(r'^file/(?P<file_id>[^/]+)/$', views.FileView.as_view(), name='file'),
    re_path(r'^shard/$', views.ShardView.as_view(), name='shard'),

    re_path(r'^file-repository-right/accept/$', views.FileRepositoryRightAcceptView.as_view(), name='file_repository_right_accept'),
    re_path(r'^file-repository-right/decline/$', views.FileRepositoryRightDeclineView.as_view(), name='file_repository_right_decline'),
    re_path(r'^file-repository-right/$', views.FileRepositoryRightView.as_view(), name='file_repository_right'),

    re_path(r'^group-file-repository-right/$', views.GroupFileRepositoryRightView.as_view(), name='group_file_repository_right'),

    re_path(r'^file-repository/download/$', views.FileRepositoryDownloadView.as_view(), name='file_repository_download'),
    re_path(r'^file-repository/upload/$', views.FileRepositoryUploadView.as_view(), name='file_repository_upload'),
    re_path(r'^file-repository/(?P<file_repository_id>[^/]+)/$', views.FileRepositoryView.as_view(), name='file_repository'),
    re_path(r'^file-repository/$', views.FileRepositoryView.as_view(), name='file_repository'),

    re_path(r'^secret/link/$', views.SecretLinkView.as_view(), name='secret_link'),

    re_path(r'^bulk-secret/$', views.BulkSecretView.as_view(), name='bulk_secret'),
    re_path(r'^secret/$', views.SecretView.as_view(), name='secret'),
    re_path(r'^secret/history/(?P<secret_id>[^/]+)/$', views.SecretHistoryView.as_view(), name='secret_history'),
    re_path(r'^secret/(?P<secret_id>[^/]+)/$', views.SecretView.as_view(), name='secret'),

    re_path(r'^history/(?P<secret_history_id>[^/]+)/$', views.HistoryView.as_view(), name='history'),

    re_path(r'^share/rights/(?P<share_id>[^/]+)/$', views.ShareRightsView.as_view(), name='share_rights'),

    re_path(r'^share/right/accept/$', views.ShareRightAcceptView.as_view(), name='share_right_accept'),
    re_path(r'^share/right/decline/$', views.ShareRightDeclineView.as_view(), name='share_right_decline'),
    re_path(r'^share/right/$', views.ShareRightView.as_view(), name='share_right'),
    re_path(r'^share/right/(?P<user_share_right_id>[^/]+)/$', views.ShareRightView.as_view(), name='share_right'),

    re_path(r'^share/link/$', views.ShareLinkView.as_view(), name='share_link'),

    re_path(r'^share/$', views.ShareView.as_view(), name='share'),
    re_path(r'^share/(?P<share_id>[^/]+)/$', views.ShareView.as_view(), name='share'),

    re_path(r'^group/$', views.GroupView.as_view(), name='group'),
    re_path(r'^group/rights/$', views.GroupRightsView.as_view(), name='group_rights'),
    re_path(r'^group/rights/(?P<group_id>[^/]+)/$', views.GroupRightsView.as_view(), name='group_rights'),
    re_path(r'^group/(?P<group_id>[^/]+)/$', views.GroupView.as_view(), name='group'),

    re_path(r'^membership/accept/$', views.MembershipAcceptView.as_view(), name='membership_accept'),
    re_path(r'^membership/decline/$', views.MembershipDeclineView.as_view(), name='membership_decline'),
    re_path(r'^membership/$', views.MembershipView.as_view(), name='membership'),

    re_path(r'^metadata-datastore/(?P<datastore_id>[^/]+)/$', views.MetadataDatastoreView.as_view(), name='metadata_datastore'),
    re_path(r'^metadata-share/(?P<share_id>[^/]+)/$', views.MetadataShareView.as_view(), name='metadata_share'),

    re_path(r'^management-command/$', views.ManagementCommandView.as_view(), name='management_command'),
    # re_path(r'^$', views.api_root),

    re_path(r'^healthcheck/$', views.HealthCheckView.as_view(), name='healthcheck'),
    re_path(r'^info/$', views.InfoView.as_view(), name='info'),

]

if settings.DEBUG:
    # URLs for development purposes only
    urlpatterns += [
        re_path(r'^coverage/(?P<path>.*)$', django.views.static.serve,
            {'document_root':join(dirname(abspath(__file__)), '..', '..', 'htmlcov')}),
    ]