"""
osivault.sign: Self-describing digital signature envelopes with allowlist-first verification.
"""

from osivault.sign.crypto import (
    sign,
    verify,
    Envelope,
    SignatureVerificationError,
    ALLOWED_SIGNATURE_ALGORITHMS,
    SIG_HEADER_PREFIX,
)

__all__ = [
    "sign",
    "verify",
    "Envelope",
    "SignatureVerificationError",
    "ALLOWED_SIGNATURE_ALGORITHMS",
    "SIG_HEADER_PREFIX",
]
