"""
Authentication handlers for OSIVault Admin Panel.
Supports Email/Password and WebAuthn / FIDO2 Hardware Security Keys (YubiKey / Passkey).
"""

import uuid
import secrets
from datetime import timedelta
from django.utils import timezone
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from osivault.admin.models import (
    OSIVaultAdminAccount,
    OSIVaultWebAuthnCredential,
    OSIVaultAdminSession,
)


class AdminAuthError(Exception):
    """Raised when admin authentication or WebAuthn verification fails."""
    pass


def create_admin_account(email: str, password: str, role: str = "admin") -> OSIVaultAdminAccount:
    """
    Helper to create an OSIVault Admin account with password hashing.
    """
    account, created = OSIVaultAdminAccount.objects.get_or_create(
        email=email,
        defaults={"role": role}
    )
    account.set_password(password)
    account.role = role
    account.is_active = True
    account.save()
    return account


def authenticate_password(email: str, password: str) -> tuple[OSIVaultAdminAccount, str]:
    """
    Authenticate admin with email and password, returning (account, session_token).
    """
    try:
        account = OSIVaultAdminAccount.objects.get(email=email, is_active=True)
    except OSIVaultAdminAccount.DoesNotExist:
        raise AdminAuthError("Invalid credentials or account is inactive.")

    if not account.check_password(password):
        raise AdminAuthError("Invalid credentials.")

    account.last_login = timezone.now()
    account.save(update_fields=["last_login"])

    session_token = secrets.token_hex(32)
    OSIVaultAdminSession.objects.create(
        account=account,
        session_token=session_token,
        expires_at=timezone.now() + timedelta(hours=24)
    )

    return account, session_token


def get_webauthn_auth_options(email: str, rp_id: str = "localhost", rp_name: str = "OneSmarter Admin") -> dict:
    """
    Generate WebAuthn authentication options for hardware security keys (YubiKey/Passkey).
    """
    try:
        account = OSIVaultAdminAccount.objects.get(email=email, is_active=True)
    except OSIVaultAdminAccount.DoesNotExist:
        raise AdminAuthError(f"No active admin account found for {email}")

    credentials = OSIVaultWebAuthnCredential.objects.filter(account=account)
    if not credentials.exists():
        raise AdminAuthError(f"No hardware security keys registered for {email}")

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
        for c in credentials
    ]

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    return {
        "challenge": bytes_to_base64url(options.challenge),
        "timeout": options.timeout,
        "rpId": options.rp_id,
        "allowCredentials": [
            {"id": c.credential_id, "type": "public-key"}
            for c in credentials
        ]
    }


def verify_webauthn_assertion(
    email: str,
    credential_id: str,
    authenticator_data_b64: str,
    client_data_json_b64: str,
    signature_b64: str,
    challenge_b64: str,
    rp_id: str = "localhost",
    origin: str = "http://localhost:3000"
) -> tuple[OSIVaultAdminAccount, str]:
    """
    Verify FIDO2 / YubiKey WebAuthn assertion signature and return (account, session_token).
    """
    try:
        account = OSIVaultAdminAccount.objects.get(email=email, is_active=True)
        cred = OSIVaultWebAuthnCredential.objects.get(account=account, credential_id=credential_id)
    except (OSIVaultAdminAccount.DoesNotExist, OSIVaultWebAuthnCredential.DoesNotExist):
        raise AdminAuthError("Security Key credential not recognized.")

    try:
        verification = verify_authentication_response(
            credential=None,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(cred.public_key),
            credential_current_sign_count=cred.sign_count,
            authenticator_data=base64url_to_bytes(authenticator_data_b64),
            client_data_json=base64url_to_bytes(client_data_json_b64),
            signature=base64url_to_bytes(signature_b64),
        )

        cred.sign_count = verification.new_sign_count
        cred.save(update_fields=["sign_count"])

        account.last_login = timezone.now()
        account.save(update_fields=["last_login"])

        session_token = secrets.token_hex(32)
        OSIVaultAdminSession.objects.create(
            account=account,
            session_token=session_token,
            expires_at=timezone.now() + timedelta(hours=24)
        )

        return account, session_token
    except Exception as e:
        raise AdminAuthError(f"Security Key verification failed: {str(e)}") from e
