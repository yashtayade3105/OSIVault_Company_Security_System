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

    def generate_registration_options(self, username: str, user_id: bytes | str | None = None, rp_id: str = None, rp_name: str = None) -> Dict[str, Any]:
        from osivault.auth.webauthn import generate_registration_options
        return generate_registration_options(
            username=username,
            user_id=user_id,
            rp_id=rp_id or self.rp_id,
            rp_name=rp_name or self.rp_name,
        )

    def verify_registration_response(
        self,
        response_data: Dict[str, Any],
        expected_challenge: bytes | str,
        expected_rp_id: str = None,
        expected_origin: str = None,
    ) -> Dict[str, Any]:
        from osivault.auth.webauthn import verify_registration_response
        rpid = expected_rp_id or self.rp_id
        orig = expected_origin or f"https://{rpid}"
        return verify_registration_response(
            response_data=response_data,
            expected_challenge=expected_challenge,
            expected_rp_id=rpid,
            expected_origin=orig,
        )


class WebAuthnAsserter:
    """
    WebAuthn / FIDO2 Hardware Key Authentication Asserter adapter.
    """
    def __init__(self, rp_id: str = "localhost"):
        self.rp_id = rp_id

    def generate_assertion_options(self, credential_ids: List[str] | str, rp_id: str = None) -> Dict[str, Any]:
        from osivault.auth.webauthn import generate_assertion_options
        return generate_assertion_options(
            credential_ids=credential_ids,
            rp_id=rp_id or self.rp_id,
        )

    def verify_assertion_response(
        self,
        credential_id: str,
        authenticator_data_b64: str,
        client_data_json_b64: str,
        signature_b64: str,
        challenge_b64: str,
        public_key_b64: str,
        expected_rp_id: str = None,
        expected_origin: str = None,
        current_sign_count: int = 0,
    ) -> Dict[str, Any]:
        from osivault.auth.webauthn import verify_assertion_response
        rpid = expected_rp_id or self.rp_id
        orig = expected_origin or f"https://{rpid}"
        return verify_assertion_response(
            credential_id=credential_id,
            authenticator_data_b64=authenticator_data_b64,
            client_data_json_b64=client_data_json_b64,
            signature_b64=signature_b64,
            challenge_b64=challenge_b64,
            public_key_b64=public_key_b64,
            expected_rp_id=rpid,
            expected_origin=orig,
            current_sign_count=current_sign_count,
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
