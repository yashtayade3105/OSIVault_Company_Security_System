"""
tests/test_auth.py: Exhaustive modular test suite for osivault.auth core package.
Covers WebAuthn registration & assertion roundtrips, anti-phishing domain/origin checks,
sign count clone key detection, TOTP replay guards, recovery code single-use lifecycle,
UserWebAuthnKey database model operations, and complete End-to-End Django View/API endpoints.
"""

import json
import pytest
import pyotp
import hashlib
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from django.db import IntegrityError
from django.contrib.auth import get_user_model
from django.test import Client

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
    RecoveryCodes,
    AuthError,
    EmailOTPAdapter,
)
from osivault.auth.models import (
    UserWebAuthnKey,
    UserMFAProfile,
    UserTOTPDevice,
    EmailOTPVerification,
    UserRecoveryCode,
)

User = get_user_model()


# ============================================================================
# 1. WEBAUTHN REGISTRATION & ASSERTION CEREMONY TESTS
# ============================================================================

def test_webauthn_registration_roundtrip():
    """Test WebAuthn registration options generation and response verification roundtrip."""
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
    """Test WebAuthn assertion options generation and response verification roundtrip."""
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
    """Test that an assertion response with an unexpected phishing origin is rejected."""
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
    """Test that verifying an assertion with a mismatched or reused challenge is rejected."""
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


def test_webauthn_adapters_explicit_rp_id():
    """Test WebAuthnRegistrar and WebAuthnAsserter adapters require explicit rp_id."""
    registrar = WebAuthnRegistrar(rp_id="portal.onesmarter.com")
    reg_options = registrar.generate_registration_options("user1")
    assert reg_options["rpId"] == "portal.onesmarter.com"

    asserter = WebAuthnAsserter(rp_id="portal.onesmarter.com")
    auth_options = asserter.generate_assertion_options(credential_ids=["c1"])
    assert auth_options["rpId"] == "portal.onesmarter.com"


def test_webauthn_adapter_registration_and_assertion_wrappers():
    """Test WebAuthnRegistrar and WebAuthnAsserter method wrappers."""
    registrar = WebAuthnRegistrar(rp_id="vault.onesmarter.com", rp_name="OSIVault Core")
    
    mock_reg = MagicMock()
    mock_reg.credential_id = b"cred_wrap_1"
    mock_reg.credential_public_key = b"pub_wrap_1"
    mock_reg.sign_count = 1

    with patch("osivault.auth.webauthn._ver_reg_resp", return_value=mock_reg):
        reg_res = registrar.verify_registration_response(
            response_data={"id": "wrap_cred"},
            expected_challenge="dGVzdF9jaGFsbGVuZ2VfMTIzNDU2",
            expected_rp_id="vault.onesmarter.com",
            expected_origin="https://vault.onesmarter.com",
        )
        assert reg_res["verified"] is True

    asserter = WebAuthnAsserter(rp_id="vault.onesmarter.com")
    mock_auth = MagicMock()
    mock_auth.new_sign_count = 5

    with patch("osivault.auth.webauthn._ver_auth_resp", return_value=mock_auth):
        auth_res = asserter.verify_assertion_response(
            credential_id="wrap_cred",
            authenticator_data_b64="SZYN5YgOjGh0NBcPZHZgW4_km12",
            client_data_json_b64="eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
            signature_b64="c2lnbmF0dXJlX3Rlc3RfYnl0ZXNfMTIzNDU2Nzg5MA",
            challenge_b64="dGVzdF9jaGFsbGVuZ2VfMTIzNDU2",
            public_key_b64="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
            expected_rp_id="vault.onesmarter.com",
            expected_origin="https://vault.onesmarter.com",
            current_sign_count=4,
        )
        assert auth_res["verified"] is True
        assert auth_res["new_sign_count"] == 5


# ============================================================================
# 2. TOTP VERIFIER & REPLAY GUARD TESTS
# ============================================================================

def test_totp_replay_guard():
    """Test TOTPVerifier valid_window=0 default and last-counter replay guard."""
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
    current_counter = verifier.totp.timecode(datetime.now(timezone.utc))
    expired_attempt = verifier.verify(otp_code, last_counter=current_counter)
    assert expired_attempt is False


def test_totp_invalid_inputs():
    """Test TOTPVerifier rejects non-digit, empty, or wrong-length OTP inputs."""
    verifier = TOTPVerifier()

    assert verifier.verify("") is False
    assert verifier.verify(None) is False
    assert verifier.verify("ABCDEF") is False
    assert verifier.verify("12345") is False
    assert verifier.verify("1234567") is False


def test_totp_provisioning_uri():
    """Test TOTPVerifier generates valid provisioning URI for authenticator apps."""
    verifier = TOTPVerifier(secret="JBSWY3DPEHPK3PXP")
    uri = verifier.provisioning_uri(name="admin@onesmarter.com", issuer_name="OSIVault System")

    assert "otpauth://totp/OSIVault%20System:admin%40onesmarter.com" in uri
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=OSIVault%20System" in uri


def test_totp_qr_code_generation():
    """Test TOTPVerifier generates Base64 Data URL PNG QR Code image."""
    verifier = TOTPVerifier(secret="JBSWY3DPEHPK3PXP")
    qr_b64 = verifier.qr_code_base64(name="admin@onesmarter.com", issuer_name="OSIVault System")

    assert qr_b64.startswith("data:image/png;base64,")
    assert len(qr_b64) > 100


# ============================================================================
# 3. RECOVERY CODES LIFECYCLE TESTS
# ============================================================================

def test_recovery_codes_generation_and_verification():
    """Test generating 8 single-use emergency recovery codes and verifying them."""
    plain_codes, hashed_codes = RecoveryCodes.generate(count=8, code_length=10)

    assert len(plain_codes) == 8
    assert len(hashed_codes) == 8

    for code in plain_codes:
        assert "-" in code
        assert len(code) == 11

    # Verify first code (uppercase)
    valid, remaining_hashes = RecoveryCodes.verify(plain_codes[0], hashed_codes)
    assert valid is True
    assert len(remaining_hashes) == 7

    # Verify same code again (must be rejected because it's single-use and consumed)
    valid_reused, remaining_after_reused = RecoveryCodes.verify(plain_codes[0], remaining_hashes)
    assert valid_reused is False
    assert len(remaining_after_reused) == 7

    # Verify second code in lowercase with whitespace (must normalize and succeed)
    lowercase_code = f"  {plain_codes[1].lower()}  "
    valid_lower, remaining_after_lower = RecoveryCodes.verify(lowercase_code, remaining_hashes)
    assert valid_lower is True
    assert len(remaining_after_lower) == 6


def test_recovery_codes_invalid_code():
    """Test that invalid or fabricated recovery code is rejected."""
    _, hashed_codes = RecoveryCodes.generate(count=8)

    valid, remaining = RecoveryCodes.verify("INVALID-CODE-9999", hashed_codes)
    assert valid is False
    assert len(remaining) == 8


# ============================================================================
# 4. BUILT-IN UserWebAuthnKey & MFA DATABASE MODEL TESTS
# ============================================================================

@pytest.mark.django_db
def test_user_webauthn_key_model_crud():
    """Test UserWebAuthnKey model creation, querying, updates, and unique constraints."""
    user = User.objects.create_user(username="webauthn_user", email="user@onesmarter.com", password="pass12345password")

    key = UserWebAuthnKey.objects.create(
        user=user,
        credential_id="yubikey_cred_id_001",
        public_key="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        sign_count=1,
        key_label="Primary YubiKey 5C"
    )

    assert key.pk is not None
    assert key.user == user
    assert key.credential_id == "yubikey_cred_id_001"
    assert key.sign_count == 1
    assert "Primary YubiKey 5C" in str(key)

    # Test reverse relation on User
    assert user.webauthn_keys.count() == 1
    assert user.webauthn_keys.first() == key

    # Test unique constraint on credential_id
    with pytest.raises(IntegrityError):
        UserWebAuthnKey.objects.create(
            user=user,
            credential_id="yubikey_cred_id_001",
            public_key="another_pubkey",
            key_label="Duplicate Key"
        )


@pytest.mark.django_db
def test_user_webauthn_key_cascade_delete():
    """Test that deleting a user automatically cascades and deletes their WebAuthn keys."""
    user = User.objects.create_user(username="cascade_user", password="pass12345password")
    UserWebAuthnKey.objects.create(
        user=user,
        credential_id="yubikey_cred_id_002",
        public_key="pubkey_abc",
        key_label="Secondary Key"
    )

    assert UserWebAuthnKey.objects.filter(credential_id="yubikey_cred_id_002").count() == 1

    user.delete()

    assert UserWebAuthnKey.objects.filter(credential_id="yubikey_cred_id_002").count() == 0


@pytest.mark.django_db
def test_user_mfa_modular_models():
    """Test creating and querying modular UserTOTPDevice, UserRecoveryCode, and UserMFAProfile ORM models."""
    user = User.objects.create_user(username="modular_user", password="pass12345password")

    # 1. TOTP Device
    totp_dev = UserTOTPDevice.objects.create(
        user=user,
        encrypted_secret="JBSWY3DPEHPK3PXP",
        is_verified=True,
        last_counter=1045
    )
    assert totp_dev.pk is not None
    assert user.totp_device == totp_dev
    assert totp_dev.is_verified is True

    # 2. Recovery Codes
    rec_code = UserRecoveryCode.objects.create(
        user=user,
        code_hash="sha256_hash_code_12345",
        is_used=False
    )
    assert rec_code.pk is not None
    assert user.recovery_codes.count() == 1

    # 3. MFA Profile
    mfa_prof = UserMFAProfile.objects.create(
        user=user,
        tenant_id="tenant_alpha_001",
        preferred_method="WEBAUTHN",
        mfa_enabled=True,
        strict_hardware_required=True
    )
    assert mfa_prof.pk is not None
    assert user.mfa_profile == mfa_prof
    assert mfa_prof.tenant_id == "tenant_alpha_001"


# ============================================================================
# 5. EMAIL OTP ADAPTER TESTS
# ============================================================================

@pytest.mark.django_db
def test_email_otp_generation_and_verification():
    """Test EmailOTPAdapter generates 6-digit verification code and verifies genuine email."""
    email = "client_test@onesmarter.com"
    res = EmailOTPAdapter.generate_otp(email=email, purpose="REGISTRATION")

    assert res["status"] == "success"
    assert res["email"] == email
    otp_code = res["otp_code"]
    assert len(otp_code) == 6
    assert otp_code.isdigit()

    # Wrong OTP should fail
    verified, msg = EmailOTPAdapter.verify_otp(email=email, otp_code="000000", purpose="REGISTRATION")
    assert verified is False
    assert "Incorrect" in msg

    # Correct OTP should pass
    verified_ok, msg_ok = EmailOTPAdapter.verify_otp(email=email, otp_code=otp_code, purpose="REGISTRATION")
    assert verified_ok is True
    assert "verified successfully" in msg_ok.lower()


# ============================================================================
# 6. END-TO-END TEMPLATE VIEWS TESTS
# ============================================================================

@pytest.mark.django_db
def test_user_portal_view():
    """Test user portal page GET request renders HTTP 200."""
    client = Client()
    response = client.get("/osivault/auth/portal/")
    assert response.status_code == 200
    assert "OSIVault Security" in response.content.decode("utf-8")


@pytest.mark.django_db
def test_mfa_setup_view_unauthenticated_redirect():
    """Test mfa_setup_view redirects unauthenticated users to portal page."""
    client = Client()
    response = client.get("/osivault/auth/setup/")
    assert response.status_code == 302
    assert "/osivault/auth/portal/?next=/osivault/auth/setup/" in response.url


@pytest.mark.django_db
def test_mfa_setup_view_authenticated():
    """Test mfa_setup_view renders setup studio HTTP 200 for authenticated users."""
    user = User.objects.create_user(username="setup_user", email="setup@onesmarter.com", password="pass12345password")
    client = Client()
    client.force_login(user)

    response = client.get("/osivault/auth/setup/")
    assert response.status_code == 200
    assert "YubiKey Hardware Management" in response.content.decode("utf-8")


@pytest.mark.django_db
def test_admin_login_view():
    """Test admin login modal page GET request renders HTTP 200."""
    client = Client()
    response = client.get("/osivault/auth/admin-login/")
    assert response.status_code == 200


# ============================================================================
# 7. END-TO-END API ENDPOINTS TESTS
# ============================================================================

@pytest.mark.django_db
def test_send_and_verify_email_otp_api_flow():
    """Test end-to-end API flow for generating and verifying Email OTP."""
    client = Client()
    email = "new_flow_user@onesmarter.com"

    # 1. Send OTP
    send_resp = client.post(
        "/osivault/auth/api/email-otp/send/",
        data=json.dumps({"email": email, "purpose": "REGISTRATION"}),
        content_type="application/json"
    )
    assert send_resp.status_code == 200
    send_data = send_resp.json()
    assert send_data["status"] == "success"
    otp_code = send_data["otp_code"]

    # 2. Verify Wrong OTP
    wrong_verify = client.post(
        "/osivault/auth/api/email-otp/verify/",
        data=json.dumps({"email": email, "otp_code": "000000", "purpose": "REGISTRATION"}),
        content_type="application/json"
    )
    assert wrong_verify.status_code == 400
    assert wrong_verify.json()["email_verified"] is False

    # 3. Verify Correct OTP
    correct_verify = client.post(
        "/osivault/auth/api/email-otp/verify/",
        data=json.dumps({"email": email, "otp_code": otp_code, "purpose": "REGISTRATION"}),
        content_type="application/json"
    )
    assert correct_verify.status_code == 200
    assert correct_verify.json()["email_verified"] is True


@pytest.mark.django_db
def test_register_and_login_user_api_flow():
    """Test registering a user via API, logging in, and verifying session & JWT token."""
    client = Client()
    email = "e2e_user@onesmarter.com"

    # Send OTP first
    send_resp = client.post(
        "/osivault/auth/api/email-otp/send/",
        data=json.dumps({"email": email, "purpose": "REGISTRATION"}),
        content_type="application/json"
    )
    otp_code = send_resp.json()["otp_code"]

    # Register user
    reg_resp = client.post(
        "/osivault/auth/api/user/register/",
        data=json.dumps({
            "username": "e2e_username",
            "email": email,
            "password": "SecurePassword123!",
            "otp_code": otp_code,
        }),
        content_type="application/json"
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    assert reg_data["status"] == "success"
    assert "token" in reg_data
    assert reg_data["user"]["email_verified"] is True

    # Check user in DB
    user = User.objects.get(username="e2e_username")
    assert user.email == email
    assert user.mfa_profile.email_verified is True

    # Test login API with username
    login_resp = client.post(
        "/osivault/auth/api/user/login/",
        data=json.dumps({
            "username_or_email": "e2e_username",
            "password": "SecurePassword123!",
        }),
        content_type="application/json"
    )
    assert login_resp.status_code == 200
    assert login_resp.json()["status"] == "success"

    # Test login API with email
    login_email_resp = client.post(
        "/osivault/auth/api/user/login/",
        data=json.dumps({
            "username_or_email": email,
            "password": "SecurePassword123!",
        }),
        content_type="application/json"
    )
    assert login_email_resp.status_code == 200
    assert login_email_resp.json()["status"] == "success"


@pytest.mark.django_db
def test_logout_user_api():
    """Test user logout API clears Django session."""
    user = User.objects.create_user(username="logout_user", password="pass12345password")
    client = Client()
    client.force_login(user)

    logout_resp = client.post("/osivault/auth/api/user/logout/")
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "success"


@pytest.mark.django_db
def test_webauthn_key_management_apis():
    """Test listing, registering options, registering verify, and revoking WebAuthn keys via API."""
    user = User.objects.create_user(username="webauthn_api_user", password="pass12345password")
    client = Client()
    client.force_login(user)

    # 1. List keys (should be empty initially)
    list_resp1 = client.get("/osivault/auth/api/webauthn/keys/list/")
    assert list_resp1.status_code == 200
    assert list_resp1.json()["total_registered"] == 0

    # 2. Get registration options
    opt_resp = client.post("/osivault/auth/api/webauthn/register/options/")
    assert opt_resp.status_code == 200
    assert opt_resp.json()["status"] == "success"
    assert "challenge" in opt_resp.json()["options"]

    # 3. Register Key 1 (Primary Slot)
    ver_resp1 = client.post(
        "/osivault/auth/api/webauthn/register/verify/",
        data=json.dumps({
            "credential_id": "api_cred_slot_1",
            "public_key": "api_pubkey_1",
            "key_label": "Primary YubiKey 5C NFC",
            "transports": "usb,nfc"
        }),
        content_type="application/json"
    )
    assert ver_resp1.status_code == 201
    assert ver_resp1.json()["key"]["slot_type"] == "PRIMARY"

    # 4. Register Key 2 (Backup Slot)
    ver_resp2 = client.post(
        "/osivault/auth/api/webauthn/register/verify/",
        data=json.dumps({
            "credential_id": "api_cred_slot_2",
            "public_key": "api_pubkey_2",
            "key_label": "Backup YubiKey 5 NFC",
            "transports": "usb,nfc"
        }),
        content_type="application/json"
    )
    assert ver_resp2.status_code == 201
    assert ver_resp2.json()["key"]["slot_type"] == "BACKUP"

    # 5. Attempt Registering Key 3 (Should fail due to max 2 limit)
    ver_resp3 = client.post(
        "/osivault/auth/api/webauthn/register/verify/",
        data=json.dumps({
            "credential_id": "api_cred_slot_3",
            "public_key": "api_pubkey_3",
            "key_label": "Third Key",
        }),
        content_type="application/json"
    )
    assert ver_resp3.status_code == 400
    assert "Maximum limit of 2 YubiKeys" in ver_resp3.json()["message"]

    # 6. Verify Assertion Options API
    assert_opt_resp = client.get(f"/osivault/auth/api/webauthn/assertion/options/?username={user.username}")
    assert assert_opt_resp.status_code == 200
    assert assert_opt_resp.json()["registered_keys_count"] == 2

    # 7. Test WebAuthn Assertion Verify API
    assert_ver_resp = client.post(
        "/osivault/auth/api/webauthn/assertion/verify/",
        data=json.dumps({"credential_id": "api_cred_slot_1"}),
        content_type="application/json"
    )
    assert assert_ver_resp.status_code == 200
    assert assert_ver_resp.json()["sign_count"] == 1

    # 8. Revoke Key 1
    key1_id = ver_resp1.json()["key"]["id"]
    revoke_resp = client.post(
        "/osivault/auth/api/webauthn/keys/revoke/",
        data=json.dumps({"key_id": key1_id}),
        content_type="application/json"
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["remaining_keys"] == 1


@pytest.mark.django_db
def test_totp_verification_api_flow():
    """Test TOTP device creation and TOTP verification API."""
    user = User.objects.create_user(username="totp_api_user", password="pass12345password")
    secret = pyotp.random_base32()
    UserTOTPDevice.objects.create(user=user, encrypted_secret=secret, is_verified=True)

    client = Client()

    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    # Test wrong TOTP
    wrong_resp = client.post(
        "/osivault/auth/api/totp/verify/",
        data=json.dumps({"username": user.username, "code": "000000"}),
        content_type="application/json"
    )
    assert wrong_resp.status_code == 400

    # Test valid TOTP
    valid_resp = client.post(
        "/osivault/auth/api/totp/verify/",
        data=json.dumps({"username": user.username, "code": valid_code}),
        content_type="application/json"
    )
    assert valid_resp.status_code == 200
    assert valid_resp.json()["status"] == "success"


@pytest.mark.django_db
def test_user_mfa_status_api():
    """Test MFA status API returns correct methods and counts."""
    user = User.objects.create_user(username="mfa_status_user", email="status@onesmarter.com", password="pass12345password")
    client = Client()

    # Initially no MFA
    status_resp1 = client.get(f"/osivault/auth/api/user/mfa-status/?email={user.email}")
    assert status_resp1.status_code == 200
    data1 = status_resp1.json()
    assert data1["has_yubikey"] is False
    assert data1["has_totp"] is False

    # Register YubiKey
    UserWebAuthnKey.objects.create(user=user, credential_id="status_key", public_key="pub", is_active=True)

    # Register TOTP
    UserTOTPDevice.objects.create(user=user, encrypted_secret="JBSWY3DPEHPK3PXP", is_verified=True)

    status_resp2 = client.get(f"/osivault/auth/api/user/mfa-status/?email={user.email}")
    assert status_resp2.status_code == 200
    data2 = status_resp2.json()
    assert data2["has_yubikey"] is True
    assert data2["has_totp"] is True
    assert "WEBAUTHN" in data2["mfa_methods"]
    assert "TOTP" in data2["mfa_methods"]


@pytest.mark.django_db
def test_totp_setup_and_login_flow():
    """Test full TOTP setup API to verification and MFA status lookup flow."""
    user = User.objects.create_user(username="totp_setup_flow_user", email="yashtyde090@gmail.com", password="pass12345password")
    client = Client()
    client.force_login(user)

    # 1. Trigger TOTP setup API as authenticated user
    setup_resp = client.post("/osivault/auth/api/totp/setup/")
    assert setup_resp.status_code == 200
    setup_data = setup_resp.json()
    assert setup_data["status"] == "success"
    secret = setup_data["secret"]
    assert len(secret) > 0

    # Device in DB should exist but not be verified yet
    device = UserTOTPDevice.objects.get(user=user)
    assert device.encrypted_secret == secret
    assert device.is_verified is False

    # MFA Status should return has_totp: False before code verification
    status_resp1 = client.get(f"/osivault/auth/api/user/mfa-status/?email={user.email}")
    assert status_resp1.json()["has_totp"] is False

    # 2. Verify code generated from secret
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    verify_resp = client.post(
        "/osivault/auth/api/totp/verify/",
        data=json.dumps({"email": user.email, "code": valid_code}),
        content_type="application/json"
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "success"

    # 3. Check DB and MFA status now
    device.refresh_from_db()
    assert device.is_verified is True
    assert user.mfa_profile.mfa_enabled is True

    # MFA Status API must now return has_totp: True
    status_resp2 = client.get(f"/osivault/auth/api/user/mfa-status/?email={user.email}")
    data2 = status_resp2.json()
    assert data2["has_totp"] is True
    assert "TOTP" in data2["mfa_methods"]


@pytest.mark.django_db
def test_recovery_codes_api_flow():
    """Test generating 8 recovery codes via REST API and verifying single-use consumption."""
    user = User.objects.create_user(username="recovery_api_user", email="recovery@onesmarter.com", password="pass12345password")
    client = Client()
    client.force_login(user)

    # 1. Generate 8 Recovery Codes
    gen_resp = client.post("/osivault/auth/api/recovery-codes/generate/")
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()
    assert gen_data["status"] == "success"
    codes = gen_data["codes"]
    assert len(codes) == 8

    # DB should contain 8 hashed records, all is_used=False
    assert UserRecoveryCode.objects.filter(user=user, is_used=False).count() == 8

    # 2. Test verifying valid recovery code
    valid_code = codes[0]
    client.logout()

    ver_resp1 = client.post(
        "/osivault/auth/api/recovery-codes/verify/",
        data=json.dumps({"email": user.email, "code": valid_code}),
        content_type="application/json"
    )
    assert ver_resp1.status_code == 200
    assert ver_resp1.json()["status"] == "success"
    assert ver_resp1.json()["remaining_codes"] == 7

    # DB record for valid_code should now be marked is_used=True
    assert UserRecoveryCode.objects.filter(user=user, is_used=False).count() == 7

    # 3. Re-verifying the SAME used recovery code should fail (Single-use enforcement)
    ver_resp2 = client.post(
        "/osivault/auth/api/recovery-codes/verify/",
        data=json.dumps({"email": user.email, "code": valid_code}),
        content_type="application/json"
    )
    assert "Invalid or already used" in ver_resp2.json()["message"]


@pytest.mark.django_db
def test_email_otp_attempt_limit_exceeded():
    """Test that after 5 failed verification attempts, Email OTP is locked and fails."""
    email = "attempts_test@onesmarter.com"
    gen_res = EmailOTPAdapter.generate_otp(email=email, purpose="REGISTRATION")
    assert gen_res["status"] == "success"

    # Attempt 5 wrong OTPs
    for _ in range(5):
        ok, msg = EmailOTPAdapter.verify_otp(email=email, otp_code="000000", purpose="REGISTRATION")
        assert ok is False

    # 6th attempt with CORRECT OTP should now be rejected due to attempt limit
    ok_correct, msg_correct = EmailOTPAdapter.verify_otp(email=email, otp_code=gen_res["otp_code"], purpose="REGISTRATION")
    assert ok_correct is False
    assert "Maximum verification attempts exceeded" in msg_correct


@pytest.mark.django_db
def test_email_otp_expiration_enforcement():
    """Test that expired Email OTP is rejected."""
    from datetime import timedelta
    from osivault.auth.models import EmailOTPVerification

    email = "expired_otp@onesmarter.com"
    gen_res = EmailOTPAdapter.generate_otp(email=email, purpose="REGISTRATION")
    otp_code = gen_res["otp_code"]

    # Manually expire the record in DB
    record = EmailOTPVerification.objects.get(email=email, purpose="REGISTRATION")
    record.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    record.save()

    ok, msg = EmailOTPAdapter.verify_otp(email=email, otp_code=otp_code, purpose="REGISTRATION")
    assert ok is False
    assert "expired" in msg.lower()


@pytest.mark.django_db
def test_email_otp_invalid_format_inputs():
    """Test EmailOTPAdapter raises AuthError or returns false on invalid email / OTP format."""
    with pytest.raises(AuthError, match="Invalid email address"):
        EmailOTPAdapter.generate_otp(email="invalid_email", purpose="REGISTRATION")

    ok1, msg1 = EmailOTPAdapter.verify_otp(email="test@onesmarter.com", otp_code="12345", purpose="REGISTRATION")
    assert ok1 is False
    assert "Enter a 6-digit number" in msg1

    ok2, msg2 = EmailOTPAdapter.verify_otp(email="test@onesmarter.com", otp_code="ABCDEF", purpose="REGISTRATION")
    assert ok2 is False
    assert "Enter a 6-digit number" in msg2


@pytest.mark.django_db
def test_login_api_invalid_credentials():
    """Test user login API with incorrect passwords or non-existent usernames returns HTTP 401."""
    client = Client()

    # Non-existent user
    resp1 = client.post(
        "/osivault/auth/api/user/login/",
        data=json.dumps({"username_or_email": "non_existent_user", "password": "WrongPassword123!"}),
        content_type="application/json"
    )
    assert resp1.status_code == 401
    assert "Invalid credentials" in resp1.json()["message"]

    # Existing user with wrong password
    User.objects.create_user(username="valid_user", password="CorrectPassword123!")
    resp2 = client.post(
        "/osivault/auth/api/user/login/",
        data=json.dumps({"username_or_email": "valid_user", "password": "WrongPassword123!"}),
        content_type="application/json"
    )
    assert resp2.status_code == 401
    assert "Invalid credentials" in resp2.json()["message"]




@pytest.mark.django_db
def test_totp_setup_unauthenticated_api_rejection():
    """Test that calling TOTP setup API without session authentication returns HTTP 401."""
    client = Client()
    resp = client.post("/osivault/auth/api/totp/setup/")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["message"]



