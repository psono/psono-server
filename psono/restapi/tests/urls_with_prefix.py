from django.urls import include, path


urlpatterns = [
    path("server/", include("restapi.urls")),
]
