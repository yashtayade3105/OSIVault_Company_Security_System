"""
osivault.auth.webauthn: Standalone FIDO2 / WebAuthn ceremony helper functions.
Supports WebAuthn registration and authentication assertion without DB or admin app dependencies.
Caller must supply rp_id and expected_origin dynamically.
"""

import uuid
from typing import Dict, Any, List
from webauthn import (
    generate_registration_options as _gen_reg_options,
    verify_registration_response as _ver_reg_resp,
    generate_authentication_options as _gen_auth_options,
    verify_authentication_response as _ver_auth_resp,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes


def generate_registration_options(
    username: str,
    rp_id: str,
    user_id: bytes | str | None = None,
    rp_name: str = "OSIVault Core",
) -> Dict[str, Any]:
    """
    Generate FIDO2 WebAuthn key registration challenge options.
    `rp_id` must be passed explicitly by caller.
    """
    if isinstance(user_id, str):
        uid_bytes = user_id.encode("utf-8")
    elif isinstance(user_id, bytes):
        uid_bytes = user_id
    else:
        uid_bytes = str(uuid.uuid4()).encode("utf-8")

    options = _gen_reg_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=uid_bytes,
        user_name=username,
    )

    return {
        "challenge": bytes_to_base64url(options.challenge),
        "rpId": rp_id,
        "rpName": rp_name,
        "userId": bytes_to_base64url(uid_bytes),
        "username": username,
        "raw_options": options,
    }


def verify_registration_response(
    response_data: Dict[str, Any],
    expected_challenge: bytes | str,
    expected_rp_id: str,
    expected_origin: str,
) -> Dict[str, Any]:
    """
    Verify FIDO2 WebAuthn key registration response.
    `expected_rp_id` and `expected_origin` are passed by caller.
    """
    if isinstance(expected_challenge, str):
        try:
            challenge_bytes = base64url_to_bytes(expected_challenge)
        except Exception:
            challenge_bytes = expected_challenge.encode("utf-8")
    else:
        challenge_bytes = expected_challenge

    verification = _ver_reg_resp(
        credential=response_data,
        expected_challenge=challenge_bytes,
        expected_rp_id=expected_rp_id,
        expected_origin=expected_origin,
    )

    return {
        "verified": True,
        "credential_id": bytes_to_base64url(verification.credential_id),
        "public_key": bytes_to_base64url(verification.credential_public_key),
        "sign_count": verification.sign_count,
        "verification": verification,
    }


def generate_assertion_options(
    credential_ids: List[str] | str,
    rp_id: str,
) -> Dict[str, Any]:
    """
    Generate FIDO2 WebAuthn authentication assertion options.
    `rp_id` must be passed explicitly by caller.
    """
    if isinstance(credential_ids, str):
        cids = [credential_ids]
    else:
        cids = credential_ids or []

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
        for cid in cids
    ]

    options = _gen_auth_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    return {
        "challenge": bytes_to_base64url(options.challenge),
        "timeout": options.timeout,
        "rpId": rp_id,
        "allowCredentials": [
            {"id": cid, "type": "public-key"}
            for cid in cids
        ],
        "raw_options": options,
    }


def verify_assertion_response(
    credential_id: str,
    authenticator_data_b64: str,
    client_data_json_b64: str,
    signature_b64: str,
    challenge_b64: str,
    public_key_b64: str,
    expected_rp_id: str,
    expected_origin: str,
    current_sign_count: int = 0,
) -> Dict[str, Any]:
    """
    Verify WebAuthn assertion signature.
    `expected_rp_id` and `expected_origin` are passed dynamically by caller.
    Checks that sign_count increased.
    """
    verification = _ver_auth_resp(
        credential=None,
        expected_challenge=base64url_to_bytes(challenge_b64),
        expected_rp_id=expected_rp_id,
        expected_origin=expected_origin,
        credential_public_key=base64url_to_bytes(public_key_b64),
        credential_current_sign_count=current_sign_count,
        authenticator_data=base64url_to_bytes(authenticator_data_b64),
        client_data_json=base64url_to_bytes(client_data_json_b64),
        signature=base64url_to_bytes(signature_b64),
    )

    return {
        "verified": True,
        "new_sign_count": verification.new_sign_count,
        "verification": verification,
    }
