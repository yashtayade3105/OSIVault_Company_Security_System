"""
tests/test_auth.py: Comprehensive unit tests for osivault.auth module.
Covers WebAuthn registration, assertion roundtrips, origin mismatch rejection,
challenge replay rejection, and TOTP replay guard.
"""

import pytest
import pyotp
from unittest.mock import patch, MagicMock
from osivault.auth.webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_assertion_options,
    verify_assertion_response,
)
from osivault.auth.adapters import (
    TOTPVerifier,
    WebAuthnRegistrar,
    WebAuthnAsserter,
)


def test_webauthn_registration_roundtrip():
    """
    Test WebAuthn registration options generation and response verification roundtrip.
    """
    options = generate_registration_options(
        username="yash@onesmarter.com",
        rp_id="mir.onesmarter.com",
        rp_name="OneSmarter MIR Portal",
    )

    assert options["username"] == "yash@onesmarter.com"
    assert options["rpId"] == "mir.onesmarter.com"
    assert options["rpName"] == "OneSmarter MIR Portal"
    assert "challenge" in options
    assert "userId" in options

    mock_verification = MagicMock()
    mock_verification.credential_id = b"cred_12345"
    mock_verification.credential_public_key = b"pubkey_67890"
    mock_verification.sign_count = 1

    with patch("osivault.auth.webauthn._ver_reg_resp", return_value=mock_verification):
        result = verify_registration_response(
            response_data={"id": "test_cred_id"},
            expected_challenge=options["challenge"],
            expected_rp_id="mir.onesmarter.com",
            expected_origin="https://mir.onesmarter.com",
        )

        assert result["verified"] is True
        assert "credential_id" in result
        assert "public_key" in result
        assert result["sign_count"] == 1


def test_webauthn_assertion_roundtrip():
    """
    Test WebAuthn assertion options generation and response verification roundtrip.
    """
    options = generate_assertion_options(
        credential_ids=["cred_id_abc123"],
        rp_id="mir.onesmarter.com",
    )

    assert options["rpId"] == "mir.onesmarter.com"
    assert "challenge" in options
    assert len(options["allowCredentials"]) == 1

    mock_verification = MagicMock()
    mock_verification.new_sign_count = 2

    with patch("osivault.auth.webauthn._ver_auth_resp", return_value=mock_verification):
        result = verify_assertion_response(
            credential_id="cred_id_abc123",
            authenticator_data_b64="YXV0aF9kYXRh",
            client_data_json_b64="Y2xpZW50X2RhdGE",
            signature_b64="c2lnbmF0dXJl",
            challenge_b64=options["challenge"],
            public_key_b64="cHVibGljX2tleQ",
            expected_rp_id="mir.onesmarter.com",
            expected_origin="https://mir.onesmarter.com",
            current_sign_count=1,
        )

        assert result["verified"] is True
        assert result["new_sign_count"] == 2


def test_webauthn_assertion_wrong_origin_rejected():
    """
    Test that an assertion response with an unexpected origin is rejected.
    """
    with patch(
        "osivault.auth.webauthn._ver_auth_resp",
        side_effect=ValueError("Origin mismatch: expected https://mir.onesmarter.com"),
    ):
        with pytest.raises(ValueError, match="Origin mismatch"):
            verify_assertion_response(
                credential_id="cred_id_abc123",
                authenticator_data_b64="YXV0aF9kYXRh",
                client_data_json_b64="Y2xpZW50X2RhdGE",
                signature_b64="c2lnbmF0dXJl",
                challenge_b64="dGVzdF9jaGFsbGVuZ2U",
                public_key_b64="cHVibGljX2tleQ",
                expected_rp_id="mir.onesmarter.com",
                expected_origin="https://mir.onesmarter.com",
            )


def test_webauthn_reused_challenge_rejected():
    """
    Test that verifying an assertion with a mismatched or reused challenge is rejected.
    """
    with patch(
        "osivault.auth.webauthn._ver_auth_resp",
        side_effect=ValueError("Invalid challenge: challenge has already been used"),
    ):
        with pytest.raises(ValueError, match="Invalid challenge"):
            verify_assertion_response(
                credential_id="cred_id_abc123",
                authenticator_data_b64="YXV0aF9kYXRh",
                client_data_json_b64="Y2xpZW50X2RhdGE",
                signature_b64="c2lnbmF0dXJl",
                challenge_b64="reused_challenge_bytes",
                public_key_b64="cHVibGljX2tleQ",
                expected_rp_id="mir.onesmarter.com",
                expected_origin="https://mir.onesmarter.com",
            )


def test_totp_replay_guard():
    """
    Test TOTPVerifier valid_window=0 default and last-counter replay guard.
    """
    secret = pyotp.random_base32()
    verifier = TOTPVerifier(secret=secret)

    otp_code = verifier.generate_otp()

    # First verification should succeed
    first_attempt = verifier.verify(otp_code, valid_window=0)
    assert first_attempt is True

    # Immediate second verification with same OTP code should be rejected by replay guard
    second_attempt = verifier.verify(otp_code, valid_window=0)
    assert second_attempt is False

    # Test explicit last_counter rejection
    from datetime import datetime, timezone
    current_counter = verifier.totp.timecode(datetime.now(timezone.utc))
    expired_attempt = verifier.verify(otp_code, last_counter=current_counter)
    assert expired_attempt is False


def test_webauthn_adapters_explicit_rp_id():
    """
    Test WebAuthnRegistrar and WebAuthnAsserter adapters require explicit rp_id.
    """
    registrar = WebAuthnRegistrar(rp_id="portal.onesmarter.com")
    reg_options = registrar.generate_registration_options("user1")
    assert reg_options["rpId"] == "portal.onesmarter.com"

    asserter = WebAuthnAsserter(rp_id="portal.onesmarter.com")
    auth_options = asserter.generate_assertion_options(credential_ids=["c1"])
    assert auth_options["rpId"] == "portal.onesmarter.com"
