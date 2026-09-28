"""
URL Configuration for OSIVault Admin API Endpoints.
"""

from django.urls import path
from osivault.admin.views import (
    admin_sign_in_view,
    webauthn_options_view,
    database_tables_view,
    table_data_view,
    osivault_modules_view,
)

urlpatterns = [
    path("api/sign-in/", admin_sign_in_view, name="osivault_admin_sign_in"),
    path("api/webauthn/options/", webauthn_options_view, name="osivault_admin_webauthn_options"),
    path("api/tables/", database_tables_view, name="osivault_admin_tables"),
    path("api/tables/<str:table_name>/", table_data_view, name="osivault_admin_table_data"),
    path("api/modules/", osivault_modules_view, name="osivault_admin_modules"),
]
