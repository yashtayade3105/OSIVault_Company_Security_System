from django.db import models
from django.conf import settings


class EmailOTPVerification(models.Model):
    """
    Email OTP Verification model for verifying genuine user email addresses during registration.
    Enforces 6-digit secure OTP, 10-minute expiration, and attempt limiting.
    """
    email = models.EmailField(db_index=True)
    otp_code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=30, default="REGISTRATION", db_index=True)
    is_verified = models.BooleanField(default=False, db_index=True)
    attempts = models.IntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "osivault_auth"
        db_table = "osivault_email_otp_verification"
        verbose_name = "Email OTP Verification"
        verbose_name_plural = "Email OTP Verifications"
        indexes = [
            models.Index(fields=["email", "purpose", "is_verified"]),
        ]

    def __str__(self):
        return f"{self.email} [{self.purpose}] - Verified: {self.is_verified}"


class UserWebAuthnKey(models.Model):
    """
    Built-in OSIVault WebAuthn Hardware Credential storage model.
    Encapsulates FIDO2 / WebAuthn YubiKey public keys bound per user and email.
    Optimized for high-concurrency (2M+ users) with compound indexing on (user, is_active).
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="webauthn_keys",
        db_index=True,
    )
    credential_id = models.CharField(max_length=512, unique=True, db_index=True)
    public_key = models.TextField()
    sign_count = models.BigIntegerField(default=0)
    key_label = models.CharField(max_length=100, default="Primary YubiKey")
    transports = models.CharField(max_length=100, default="usb,nfc")
    aaguid = models.CharField(max_length=64, blank=True, default="")
    is_active = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "osivault_auth"
        db_table = "osivault_webauthn_key"
        verbose_name = "User WebAuthn Key"
        verbose_name_plural = "User WebAuthn Keys"
        indexes = [
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["credential_id"]),
        ]

    def __str__(self):
        return f"{self.user} - {self.key_label} [{self.credential_id[:12]}...]"


class UserTOTPDevice(models.Model):
    """
    Modular TOTP secret seed and replay guard model per user and email.
    Ensures 1 active TOTP configuration per user with monotonic timecode replay protection.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="totp_device",
        db_index=True,
    )
    encrypted_secret = models.CharField(max_length=256, help_text="Base32 TOTP secret seed or OSIVault encrypted secret")
    is_verified = models.BooleanField(default=False, db_index=True)
    last_counter = models.BigIntegerField(default=0, help_text="Replay guard counter tracking")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "osivault_auth"
        db_table = "osivault_totp_device"
        verbose_name = "User TOTP Device"
        verbose_name_plural = "User TOTP Devices"

    def __str__(self):
        return f"{self.user} - TOTP Verified: {self.is_verified}"


class UserRecoveryCode(models.Model):
    """
    Single-use emergency break-glass recovery code storage per user.
    Codes are stored as SHA-256 hashes for zero-knowledge security.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="recovery_codes",
        db_index=True,
    )
    code_hash = models.CharField(max_length=128, db_index=True)
    is_used = models.BooleanField(default=False, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "osivault_auth"
        db_table = "osivault_recovery_code"
        verbose_name = "User Recovery Code"
        verbose_name_plural = "User Recovery Codes"
        indexes = [
            models.Index(fields=["user", "is_used"]),
            models.Index(fields=["code_hash"]),
        ]

    def __str__(self):
        return f"{self.user} - Code Hash [{self.code_hash[:10]}...] (Used: {self.is_used})"


class UserMFAProfile(models.Model):
    """
    User-level MFA posture preferences, email verification status, and multi-tenant controls.
    Supports enterprise multi-tenant isolation with tenant_id indexing.
    """
    METHOD_CHOICES = (
        ("WEBAUTHN", "FIDO2 / WebAuthn Hardware Key"),
        ("TOTP", "Authenticator App (TOTP)"),
        ("BOTH", "WebAuthn + TOTP Dual MFA"),
        ("NONE", "Disabled"),
    )
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mfa_profile",
        db_index=True,
    )
    email_verified = models.BooleanField(default=False, db_index=True)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    tenant_id = models.CharField(max_length=100, default="default", db_index=True)
    preferred_method = models.CharField(max_length=20, choices=METHOD_CHOICES, default="NONE")
    mfa_enabled = models.BooleanField(default=False, db_index=True)
    strict_hardware_required = models.BooleanField(default=False)
    last_mfa_login_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "osivault_auth"
        db_table = "osivault_mfa_profile"
        verbose_name = "User MFA Profile"
        verbose_name_plural = "User MFA Profiles"
        indexes = [
            models.Index(fields=["tenant_id", "mfa_enabled"]),
            models.Index(fields=["email_verified"]),
        ]

    def __str__(self):
        return f"{self.user} - Email Verified: {self.email_verified} (MFA Enabled: {self.mfa_enabled})"
