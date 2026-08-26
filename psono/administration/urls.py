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
from . import views
from django.urls import URLPattern
from typing import List

urlpatterns = []  # type: List[URLPattern]

if settings.MANAGEMENT_ENABLED:
    # URLs for management servers purposes only
    urlpatterns += [
        re_path(
            r"^authorization/$",
            views.AuthorizationView.as_view(),
            name="admin_authorization",
        ),
        re_path(
            r"^capability/$",
            views.CapabilityView.as_view(),
            name="admin_capability",
        ),
        re_path(
            r"^tenant/(?P<tenant_id>[^/]+)/$",
            views.TenantView.as_view(),
            name="admin_tenant",
        ),
        re_path(r"^tenant/$", views.TenantView.as_view(), name="admin_tenant"),
        re_path(
            r"^tenant-membership/$",
            views.TenantMembershipView.as_view(),
            name="admin_tenant_membership",
        ),
        re_path(
            r"^administrative-role/(?P<role_id>[^/]+)/$",
            views.AdministrativeRoleView.as_view(),
            name="admin_administrative_role",
        ),
        re_path(
            r"^administrative-role/$",
            views.AdministrativeRoleView.as_view(),
            name="admin_administrative_role",
        ),
        re_path(
            r"^administrative-role-assignment/(?P<assignment_id>[^/]+)/$",
            views.AdministrativeRoleAssignmentView.as_view(),
            name="admin_administrative_role_assignment",
        ),
        re_path(
            r"^administrative-role-assignment/$",
            views.AdministrativeRoleAssignmentView.as_view(),
            name="admin_administrative_role_assignment",
        ),
        re_path(r"^info/$", views.InfoView.as_view(), name="admin_info"),
        re_path(
            r"^user/(?P<user_id>[^/]+)/$", views.UserView.as_view(), name="admin_user"
        ),
        re_path(r"^user/$", views.UserView.as_view(), name="admin_user"),
        re_path(
            r"^yubikey-otp/$", views.YubikeyOTPView.as_view(), name="admin_yubikey_otp"
        ),
        re_path(r"^webautn/$", views.WebAuthnView.as_view(), name="admin_webauthn"),
        re_path(
            r"^google-authenticator/$",
            views.GaView.as_view(),
            name="admin_google_authenticator",
        ),
        re_path(
            r"^recovery-code/$",
            views.RecoveryCodeView.as_view(),
            name="admin_recovery_code",
        ),
        re_path(
            r"^emergency-code/$",
            views.EmergencyCodeView.as_view(),
            name="admin_emergency_code",
        ),
        re_path(r"^duo/$", views.DuoView.as_view(), name="admin_duo"),
        re_path(r"^ivalt/$", views.IvaltView.as_view(), name="admin_ivalt"),
        re_path(
            r"^session/(?P<session_id>[^/]+)/$",
            views.SessionView.as_view(),
            name="admin_session",
        ),
        re_path(r"^session/$", views.SessionView.as_view(), name="admin_session"),
        re_path(
            r"^security-report/(?P<security_report_id>[^/]+)/",
            views.SecurityReportView.as_view(),
            name="admin_security_report",
        ),
        re_path(
            r"^security-report/$",
            views.SecurityReportView.as_view(),
            name="admin_security_report",
        ),
        re_path(
            r"^group/(?P<group_id>[^/]+)/$",
            views.GroupView.as_view(),
            name="admin_group",
        ),
        re_path(r"^group/$", views.GroupView.as_view(), name="admin_group"),
        re_path(
            r"^group/(?P<group_id>[^/]+)/$",
            views.GroupView.as_view(),
            name="admin_group",
        ),
        re_path(
            r"^group-share-right/$",
            views.GroupShareRightView.as_view(),
            name="admin_group_share_right",
        ),
        re_path(
            r"^link-share/$", views.LinkShareView.as_view(), name="admin_link_share"
        ),
        re_path(
            r"^membership/$", views.MembershipView.as_view(), name="admin_membership"
        ),
        re_path(
            r"^stats/browser/$", views.StatsBrowserView.as_view(), name="stats_browser"
        ),
        re_path(
            r"^stats/device/$", views.StatsDeviceView.as_view(), name="stats_device"
        ),
        re_path(r"^stats/os/$", views.StatsOsView.as_view(), name="stats_os"),
        re_path(
            r"^fileserver-cluster/configuration/$",
            views.FileserverClusterConfigView.as_view(),
            name="admin_fileserver_cluster_configuration",
        ),
        re_path(
            r"^fileserver-cluster/(?P<cluster_id>[^/]+)/$",
            views.FileserverClusterView.as_view(),
            name="admin_fileserver_cluster",
        ),
        re_path(
            r"^fileserver-cluster/$",
            views.FileserverClusterView.as_view(),
            name="admin_fileserver_cluster",
        ),
        re_path(
            r"^fileserver-shard/(?P<shard_id>[^/]+)/$",
            views.FileserverShardView.as_view(),
            name="admin_fileserver_shard",
        ),
        re_path(
            r"^fileserver-shard/$",
            views.FileserverShardView.as_view(),
            name="admin_fileserver_shard",
        ),
        re_path(
            r"^fileserver-cluster-shard-link/$",
            views.FileserverClusterShardLinkView.as_view(),
            name="admin_fileserver_cluster_shard_link",
        ),
        re_path(
            r"^fileserver/(?P<fileserver_id>[^/]+)/$",
            views.FileserverView.as_view(),
            name="admin_fileserver",
        ),
        re_path(
            r"^fileserver/$",
            views.FileserverView.as_view(),
            name="admin_fileserver",
        ),
        re_path(
            r"^stats/two-factor/$",
            views.StatsTwoFactorView.as_view(),
            name="stats_two_factor",
        ),
    ]
