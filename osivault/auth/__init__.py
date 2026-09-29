"""
osivault.auth: Second-factor adapters for privileged and ordinary accounts.
"""

from osivault.auth.adapters import (
    TOTPVerifier,
    WebAuthnRegistrar,
    WebAuthnAsserter,
    RecoveryCodes,
    AuthError,
)

__all__ = [
    "TOTPVerifier",
    "WebAuthnRegistrar",
    "WebAuthnAsserter",
    "RecoveryCodes",
    "AuthError",
]
