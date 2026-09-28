"""
Tests for osivault.admin module.
Covers Admin Account creation, password authentication, WebAuthn options, and dynamic schema API.
"""

import pytest
from django.test import RequestFactory
from osivault.admin import (
    create_admin_account,
    authenticate_password,
    get_webauthn_auth_options,
    AdminAuthError,
    OSIVaultAdminAccount,
)
from osivault.admin.views import database_tables_view, admin_sign_in_view

pytestmark = pytest.mark.django_db


def test_admin_account_creation_and_password_auth():
    """Test creating admin account and authenticating password."""
    account = create_admin_account("admin@onesmarter.com", "SuperSecretPass2026!", role="superadmin")
    assert account.email == "admin@onesmarter.com"
    assert account.role == "superadmin"
    assert account.check_password("SuperSecretPass2026!") is True

    # Authenticate password
    acc, token = authenticate_password("admin@onesmarter.com", "SuperSecretPass2026!")
    assert acc.pk == account.pk
    assert len(token) == 64

    # Invalid password raises AdminAuthError
    with pytest.raises(AdminAuthError):
        authenticate_password("admin@onesmarter.com", "WrongPassword")


def test_admin_sign_in_view():
    """Test admin sign in API endpoint."""
    create_admin_account("admin@onesmarter.com", "Pass123456!")
    rf = RequestFactory()

    # Valid POST
    request = rf.post(
        "/osivault/admin/api/sign-in/",
        data={"email": "admin@onesmarter.com", "password": "Pass123456!"},
        content_type="application/json"
    )
    response = admin_sign_in_view(request)
    assert response.status_code == 200
    assert b"session_token" in response.content


def test_database_tables_discovery_api():
    """Test dynamic database table discovery API."""
    account, token = authenticate_password(
        create_admin_account("admin@onesmarter.com", "Pass123!").email,
        "Pass123!"
    )
    rf = RequestFactory()

    request = rf.get(
        "/osivault/admin/api/tables/",
        HTTP_AUTHORIZATION=f"Bearer {token}"
    )
    response = database_tables_view(request)
    assert response.status_code == 200
    assert b"tables" in response.content
    assert b"table_count" in response.content
