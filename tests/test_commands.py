"""
Tests for OSIVault Management Commands (createosivaultsuperuser and createosivaultadmin).
"""

import pytest
from io import StringIO
from django.core.management import call_command
from django.core.management.base import CommandError
from osivault.admin.models import OSIVaultAdminAccount

pytestmark = pytest.mark.django_db


def test_createosivaultsuperuser_command_non_interactive():
    """Test creating an OSIVault superuser via non-interactive CLI flags."""
    out = StringIO()
    call_command(
        "createosivaultsuperuser",
        "--noinput",
        "--email=cliadmin@onesmarter.com",
        "--password=CLIPassword123!",
        "--role=superadmin",
        stdout=out
    )

    account = OSIVaultAdminAccount.objects.get(email="cliadmin@onesmarter.com")
    assert account.role == "superadmin"
    assert account.check_password("CLIPassword123!") is True
    assert "created successfully" in out.getvalue()


def test_createosivaultadmin_alias_command():
    """Test the createosivaultadmin alias command."""
    out = StringIO()
    call_command(
        "createosivaultadmin",
        "--noinput",
        "--email=aliasadmin@onesmarter.com",
        "--password=AliasPassword123!",
        stdout=out
    )

    account = OSIVaultAdminAccount.objects.get(email="aliasadmin@onesmarter.com")
    assert account.role == "superuser"
    assert account.check_password("AliasPassword123!") is True


def test_createosivaultsuperuser_missing_args_raises_error():
    """Test that missing required arguments in non-interactive mode raises CommandError."""
    with pytest.raises(CommandError):
        call_command("createosivaultsuperuser", "--noinput")
