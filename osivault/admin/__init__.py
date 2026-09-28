"""
osivault.admin: Privileged Admin Accounts, FIDO2/WebAuthn YubiKey Authentication, and Dynamic Database Explorer.
"""

def __getattr__(name):
    if name in {"OSIVaultAdminAccount", "OSIVaultWebAuthnCredential", "OSIVaultAdminSession"}:
        from osivault.admin import models
        return getattr(models, name)
    if name in {
        "create_admin_account",
        "authenticate_password",
        "get_webauthn_auth_options",
        "verify_webauthn_assertion",
        "AdminAuthError",
    }:
        from osivault.admin import auth
        return getattr(auth, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "OSIVaultAdminAccount",
    "OSIVaultWebAuthnCredential",
    "OSIVaultAdminSession",
    "create_admin_account",
    "authenticate_password",
    "get_webauthn_auth_options",
    "verify_webauthn_assertion",
    "AdminAuthError",
]
