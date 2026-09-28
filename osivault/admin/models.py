"""
OSIVault Admin Account, WebAuthn/Passkey Credential, and Session models.
Automatically managed when osivault.admin is included in a Django application.
"""

from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone


class OSIVaultAdminAccount(models.Model):
    """
    Administrator account for accessing OSIVault Desktop Admin Panel.
    Stored directly inside consuming application's database.
    """
    email = models.EmailField(unique=True, db_index=True)
    password_hash = models.CharField(max_length=255)
    role = models.CharField(max_length=50, default="admin")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "osivault_admin_account"
        verbose_name = "OSIVault Admin Account"
        verbose_name_plural = "OSIVault Admin Accounts"

    def set_password(self, raw_password: str) -> None:
        self.password_hash = make_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password_hash)

    def __str__(self):
        return f"{self.email} ({self.role})"


class OSIVaultWebAuthnCredential(models.Model):
    """
    FIDO2 / WebAuthn Hardware Security Key (YubiKey / Passkey) credential record.
    Enables hardware key authentication for privileged admin access.
    """
    account = models.ForeignKey(
        OSIVaultAdminAccount,
        on_delete=models.CASCADE,
        related_name="webauthn_credentials"
    )
    credential_id = models.CharField(max_length=512, unique=True, db_index=True)
    public_key = models.TextField()
    sign_count = models.BigIntegerField(default=0)
    device_name = models.CharField(max_length=100, default="YubiKey / Security Key")
    aaguid = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "osivault_webauthn_credential"
        verbose_name = "OSIVault WebAuthn Credential"
        verbose_name_plural = "OSIVault WebAuthn Credentials"

    def __str__(self):
        return f"{self.account.email} - {self.device_name}"


class OSIVaultAdminSession(models.Model):
    """
    Active login session token for OSIVault Desktop Admin Panel.
    """
    account = models.ForeignKey(
        OSIVaultAdminAccount,
        on_delete=models.CASCADE,
        related_name="admin_sessions"
    )
    session_token = models.CharField(max_length=128, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        db_table = "osivault_admin_session"
        verbose_name = "OSIVault Admin Session"

    def is_valid(self) -> bool:
        return self.expires_at > timezone.now()
