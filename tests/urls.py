from django.urls import path, include

urlpatterns = [
    path("osivault/auth/", include("osivault.auth.urls")),
]
