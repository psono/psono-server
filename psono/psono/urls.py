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
from django.urls import re_path, include, path
from django.conf import settings
from rest_framework import routers

router = routers.DefaultRouter()

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    #re_path(r'^', include(router.urls)),
    #re_path(r'^accounts/', include('allauth.urls')),
    #re_path(r'^rest-auth/', include('rest_auth.urls')),
    #re_path(r'^rest-auth/registration/', include('rest_auth.registration.urls')),
    re_path(r'^', include('restapi.urls')),
    re_path(r'^admin/', include('administration.urls')),
    re_path(r'^fileserver/', include('fileserver.urls')),
    re_path(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]

if settings.URL_PREFIX:
    urlpatterns = [path(f'{settings.URL_PREFIX}', include(urlpatterns))]