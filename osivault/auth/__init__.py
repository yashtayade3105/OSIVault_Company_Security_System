"""
osivault.auth: Second-factor adapters and built-in hardware credential models.
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
