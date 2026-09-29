"""
osivault.auth: Second-factor adapters for privileged and ordinary accounts.
Provides TOTP verification, WebAuthn registration & assertion, and Recovery Code generators.
"""

import pyotp
import secrets
import hashlib
from typing import List, Tuple, Dict, Any


class AuthError(Exception):
    """Base exception for osivault.auth adapters."""
    pass


class TOTPVerifier:
    """
    TOTP (Time-based One-Time Password) verifier with replay protection window.
    """
    def __init__(self, secret: str = None):
        self.secret = secret or pyotp.random_base32()
        self.totp = pyotp.TOTP(self.secret)

    def generate_otp(self) -> str:
        return self.totp.now()

    def verify(self, otp_code: str, valid_window: int = 1) -> bool:
        if not otp_code or not str(otp_code).isdigit():
            return False
        return self.totp.verify(str(otp_code), valid_window=valid_window)

    def provisioning_uri(self, name: str, issuer_name: str = "OSIVault") -> str:
        return self.totp.provisioning_uri(name=name, issuer_name=issuer_name)


class WebAuthnRegistrar:
    """
    WebAuthn / FIDO2 Hardware Key Registration adapter.
    """
    def __init__(self, rp_id: str = "localhost", rp_name: str = "OSIVault Core"):
        self.rp_id = rp_id
        self.rp_name = rp_name

    def generate_registration_options(self, username: str) -> Dict[str, Any]:
        from webauthn import generate_registration_options
        from webauthn.helpers import bytes_to_base64url
        import uuid

        user_id = str(uuid.uuid4()).encode("utf-8")
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id,
            user_name=username,
        )
        return {
            "challenge": bytes_to_base64url(options.challenge),
            "rpId": self.rp_id,
            "rpName": self.rp_name,
            "userId": bytes_to_base64url(user_id),
            "username": username,
        }


class WebAuthnAsserter:
    """
    WebAuthn / FIDO2 Hardware Key Authentication Asserter adapter.
    """
    def __init__(self, rp_id: str = "localhost"):
        self.rp_id = rp_id

    def get_auth_options(self, email: str) -> Dict[str, Any]:
        from osivault.admin.auth import get_webauthn_auth_options
        return get_webauthn_auth_options(email=email, rp_id=self.rp_id)

    def verify_assertion(
        self,
        email: str,
        credential_id: str,
        authenticator_data_b64: str,
        client_data_json_b64: str,
        signature_b64: str,
        challenge_b64: str,
    ) -> Tuple[Any, str]:
        from osivault.admin.auth import verify_webauthn_assertion
        return verify_webauthn_assertion(
            email=email,
            credential_id=credential_id,
            authenticator_data_b64=authenticator_data_b64,
            client_data_json_b64=client_data_json_b64,
            signature_b64=signature_b64,
            challenge_b64=challenge_b64,
            rp_id=self.rp_id,
        )


class RecoveryCodes:
    """
    Secure single-use emergency recovery code generator and hasher.
    """
    @staticmethod
    def generate(count: int = 8, code_length: int = 10) -> Tuple[List[str], List[str]]:
        raw_codes = []
        hashed_codes = []
        for _ in range(count):
            raw = secrets.token_hex(code_length // 2).upper()
            raw_formatted = f"{raw[:5]}-{raw[5:]}"
            raw_codes.append(raw_formatted)
            hashed_codes.append(hashlib.sha256(raw_formatted.encode("utf-8")).hexdigest())
        return raw_codes, hashed_codes

    @staticmethod
    def verify(raw_code: str, hashed_codes: List[str]) -> Tuple[bool, List[str]]:
        raw_code = str(raw_code).strip().upper()
        hashed_input = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
        if hashed_input in hashed_codes:
            updated_list = [h for h in hashed_codes if h != hashed_input]
            return True, updated_list
        return False, hashed_codes
