"""
Comprehensive End-to-End Test Suite for osivault.tokens module.
Covers 60+ rigorous test cases spanning:
1. RSA & Ed25519 Token Issuance & Verification Roundtrips
2. Claims Preservation, Unicode, Multilingual, & Complex Data Types
3. Expiration (exp), Not Before (nbf), Issued At (iat), & Unique JTI Enforcement
4. Issuer (iss) Validation & Strict Mismatch Handling
5. RFC 7517 & RFC 8037 JWKS Document Generation & Multi-Key Resolution
6. Zero-Downtime Key Rotation (rotate) & Cryptographic Independence
7. Security Attacks: Signature Tampering, Payload Escalation, Alg None/HS256 Confusion
8. Malformed Inputs: Missing Dots, Corrupted Base64, Non-String Tokens, Bad Formats
9. High-Volume Batch Stress Testing & JTI Collision Prevention
"""

import time
import base64
import json
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from osivault.tokens import issue, verify, jwks_document, rotate, TokenError
from osivault.tokens.jwt import _int_to_base64url, _base64url_to_int


@pytest.fixture
def rsa_keys():
    """Generates a standard 2048-bit RSA keypair for testing."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def ed25519_keys():
    """Generates an Ed25519 keypair for testing."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


# ==============================================================================
# SECTION 1: Standard Issuance and Verification Roundtrips (Tests 1 - 10)
# ==============================================================================

def test_rsa_rs256_standard_roundtrip(rsa_keys):
    priv_key, pub_key = rsa_keys
    claims = {"user_id": "usr_9981", "role": "admin", "tenant": "onesmarter"}
    token = issue(claims, private_key=priv_key, key_id="auth-key-1", ttl_seconds=3600, alg="RS256")
    assert isinstance(token, str)

    decoded = verify(token, public_key_or_jwks=pub_key)
    assert decoded["user_id"] == "usr_9981"
    assert decoded["role"] == "admin"
    assert decoded["tenant"] == "onesmarter"
    assert "exp" in decoded
    assert "iat" in decoded
    assert "jti" in decoded


def test_ed25519_standard_roundtrip(ed25519_keys):
    priv_key, pub_key = ed25519_keys
    claims = {"sub": "ed25519_subject", "scope": "read:all"}
    token = issue(claims, private_key=priv_key, key_id="ed-key-1", alg="Ed25519")
    decoded = verify(token, public_key_or_jwks=pub_key)
    assert decoded["sub"] == "ed25519_subject"
    assert decoded["scope"] == "read:all"


def test_default_system_key_automatic_issuance():
    claims = {"sub": "system_auto_key_user"}
    token = issue(claims)
    assert isinstance(token, str)
    decoded = verify(token)
    assert decoded["sub"] == "system_auto_key_user"


def test_custom_key_id_propagation(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "kid_test"}, private_key=priv_key, key_id="custom-kid-xyz")
    parts = token.split(".")
    header_json = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8"))
    assert header_json["kid"] == "custom-kid-xyz"
    decoded = verify(token, public_key_or_jwks=pub_key)
    assert decoded["sub"] == "kid_test"


def test_token_compact_serialization_structure(rsa_keys):
    priv_key, _ = rsa_keys
    token = issue({"sub": "format_test"}, private_key=priv_key)
    parts = token.split(".")
    assert len(parts) == 3
    for p in parts:
        assert len(p) > 0
        assert "=" not in p  # Base64URL unpadded check


def test_iat_claim_auto_injection(rsa_keys):
    priv_key, pub_key = rsa_keys
    before = int(time.time())
    token = issue({"sub": "iat_test"}, private_key=priv_key)
    after = int(time.time())
    decoded = verify(token, public_key_or_jwks=pub_key)
    assert before <= decoded["iat"] <= after


def test_jti_claim_auto_generation_uniqueness(rsa_keys):
    priv_key, pub_key = rsa_keys
    token1 = issue({"sub": "user_a"}, private_key=priv_key)
    token2 = issue({"sub": "user_a"}, private_key=priv_key)
    dec1 = verify(token1, public_key_or_jwks=pub_key)
    dec2 = verify(token2, public_key_or_jwks=pub_key)
    assert "jti" in dec1 and "jti" in dec2
    assert dec1["jti"] != dec2["jti"]
    assert len(dec1["jti"]) >= 16


def test_custom_claims_preservation_types(rsa_keys):
    priv_key, pub_key = rsa_keys
    claims = {
        "str_claim": "hello",
        "int_claim": 42,
        "float_claim": 3.14159,
        "bool_claim": True,
        "none_claim": None,
        "list_claim": [1, 2, "three", False],
        "dict_claim": {"nested_key": "nested_value", "level": 2},
    }
    token = issue(claims, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key)
    for k, v in claims.items():
        assert decoded[k] == v


def test_empty_claims_dict_handling(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({}, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key)
    assert "exp" in decoded
    assert "iat" in decoded
    assert "jti" in decoded


def test_large_payload_claims_handling(rsa_keys):
    priv_key, pub_key = rsa_keys
    large_claims = {f"field_{i}": f"data_value_{i}" * 10 for i in range(100)}
    token = issue(large_claims, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key)
    assert len(decoded) >= 100
    assert decoded["field_50"] == "data_value_50" * 10


# ==============================================================================
# SECTION 2: Expiration, Not Before (NBF), and Timing Checks (Tests 11 - 18)
# ==============================================================================

def test_custom_ttl_seconds_calculation(rsa_keys):
    priv_key, pub_key = rsa_keys
    ttl = 7200  # 2 hours
    now = int(time.time())
    token = issue({"sub": "ttl_user"}, private_key=priv_key, ttl_seconds=ttl)
    decoded = verify(token, public_key_or_jwks=pub_key)
    assert abs(decoded["exp"] - (now + ttl)) <= 2


def test_negative_ttl_immediate_expiry_rejection(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "neg_ttl"}, private_key=priv_key, ttl_seconds=-10)
    with pytest.raises(TokenError) as exc_info:
        verify(token, public_key_or_jwks=pub_key)
    assert "expired" in str(exc_info.value).lower()


def test_zero_ttl_rejection(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "zero_ttl"}, private_key=priv_key, ttl_seconds=0)
    # Token expired at the exact current second or past
    time.sleep(0.01)
    with pytest.raises(TokenError) as exc_info:
        verify(token, public_key_or_jwks=pub_key)
    assert "expired" in str(exc_info.value).lower()


def test_explicit_past_exp_claim_rejection(rsa_keys):
    priv_key, pub_key = rsa_keys
    past_time = int(time.time()) - 300
    token = issue({"sub": "past_exp", "exp": past_time}, private_key=priv_key)
    with pytest.raises(TokenError) as exc_info:
        verify(token, public_key_or_jwks=pub_key)
    assert "expired" in str(exc_info.value).lower()


def test_explicit_future_exp_claim_acceptance(rsa_keys):
    priv_key, pub_key = rsa_keys
    future_time = int(time.time()) + 10000
    token = issue({"sub": "future_exp", "exp": future_time}, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key)
    assert decoded["exp"] == future_time


def test_nbf_claim_in_future_rejection(rsa_keys):
    priv_key, pub_key = rsa_keys
    future_nbf = int(time.time()) + 600  # Valid 10 mins from now
    token = issue({"sub": "future_nbf", "nbf": future_nbf}, private_key=priv_key)
    with pytest.raises(TokenError) as exc_info:
        verify(token, public_key_or_jwks=pub_key)
    assert "not valid yet" in str(exc_info.value).lower()


def test_nbf_claim_in_past_acceptance(rsa_keys):
    priv_key, pub_key = rsa_keys
    past_nbf = int(time.time()) - 600
    token = issue({"sub": "past_nbf", "nbf": past_nbf}, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key)
    assert decoded["nbf"] == past_nbf


def test_nbf_and_exp_combined_valid_window(rsa_keys):
    priv_key, pub_key = rsa_keys
    now = int(time.time())
    token = issue({"sub": "window_user", "nbf": now - 100, "exp": now + 100}, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key)
    assert decoded["sub"] == "window_user"


# ==============================================================================
# SECTION 3: Issuer (iss) Validation & Strict Matching (Tests 19 - 24)
# ==============================================================================

def test_matching_expected_issuer_succeeds(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "iss_valid", "iss": "https://auth.onesmarter.com"}, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key, expected_issuer="https://auth.onesmarter.com")
    assert decoded["sub"] == "iss_valid"


def test_mismatched_expected_issuer_fails(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "iss_invalid", "iss": "https://auth.onesmarter.com"}, private_key=priv_key)
    with pytest.raises(TokenError) as exc_info:
        verify(token, public_key_or_jwks=pub_key, expected_issuer="https://other.auth.com")
    assert "issuer mismatch" in str(exc_info.value).lower()


def test_expected_issuer_required_but_missing_in_token_fails(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "no_iss"}, private_key=priv_key)
    with pytest.raises(TokenError) as exc_info:
        verify(token, public_key_or_jwks=pub_key, expected_issuer="https://auth.onesmarter.com")
    assert "issuer mismatch" in str(exc_info.value).lower()


def test_token_has_issuer_but_expected_issuer_none_succeeds(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "has_iss", "iss": "arbitrary_issuer"}, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key, expected_issuer=None)
    assert decoded["iss"] == "arbitrary_issuer"


def test_issuer_case_sensitivity_enforcement(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"iss": "OneSmarter.Auth"}, private_key=priv_key)
    with pytest.raises(TokenError):
        verify(token, public_key_or_jwks=pub_key, expected_issuer="onesmarter.auth")


def test_issuer_whitespace_sensitivity_enforcement(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"iss": "onesmarter.auth "}, private_key=priv_key)
    with pytest.raises(TokenError):
        verify(token, public_key_or_jwks=pub_key, expected_issuer="onesmarter.auth")


# ==============================================================================
# SECTION 4: RFC 7517 & RFC 8037 JWKS Document Generation & Verify (Tests 25 - 34)
# ==============================================================================

def test_jwks_document_single_rsa_key(rsa_keys):
    _, pub_key = rsa_keys
    jwks = jwks_document([(pub_key, "key-rsa-01", "RS256")])
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    k = jwks["keys"][0]
    assert k["kty"] == "RSA"
    assert k["kid"] == "key-rsa-01"
    assert k["use"] == "sig"
    assert k["alg"] == "RS256"
    assert "n" in k and "e" in k


def test_jwks_document_multiple_rsa_keys(rsa_keys):
    _, pub1 = rsa_keys
    _, pub2 = rsa.generate_private_key(65537, 2048).public_key(), rsa.generate_private_key(65537, 2048).public_key()
    jwks = jwks_document([(pub1, "k1", "RS256"), (pub2, "k2", "RS256")])
    assert len(jwks["keys"]) == 2
    assert jwks["keys"][0]["kid"] == "k1"
    assert jwks["keys"][1]["kid"] == "k2"


def test_jwks_document_ed25519_key_rfc8037(ed25519_keys):
    _, pub_key = ed25519_keys
    jwks = jwks_document([(pub_key, "ed-key-01", "Ed25519")])
    assert len(jwks["keys"]) == 1
    k = jwks["keys"][0]
    assert k["kty"] == "OKP"
    assert k["crv"] == "Ed25519"
    assert k["kid"] == "ed-key-01"
    assert "x" in k
    assert len(k["x"]) > 0


def test_jwks_document_mixed_rsa_and_ed25519_keys(rsa_keys, ed25519_keys):
    _, rsa_pub = rsa_keys
    _, ed_pub = ed25519_keys
    jwks = jwks_document([(rsa_pub, "rsa-1", "RS256"), (ed_pub, "ed-1", "Ed25519")])
    assert len(jwks["keys"]) == 2
    assert jwks["keys"][0]["kty"] == "RSA"
    assert jwks["keys"][1]["kty"] == "OKP"


def test_jwks_document_fields_conformance(rsa_keys):
    _, pub_key = rsa_keys
    jwks = jwks_document([(pub_key, "test-kid", "RS256")])
    k = jwks["keys"][0]
    expected_fields = {"kty", "use", "alg", "kid", "n", "e"}
    assert expected_fields.issubset(k.keys())


def test_int_to_base64url_and_inverse_conversion():
    test_values = [1, 65537, 2**256 - 1, 2**2048 - 12345]
    for val in test_values:
        b64 = _int_to_base64url(val)
        recovered = _base64url_to_int(b64)
        assert recovered == val


def test_verify_using_jwks_dict_exact_kid_match(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "jwks_kid_match"}, private_key=priv_key, key_id="key-kid-target")
    other_pub = rsa.generate_private_key(65537, 2048).public_key()
    jwks = jwks_document([(other_pub, "key-other", "RS256"), (pub_key, "key-kid-target", "RS256")])
    decoded = verify(token, public_key_or_jwks=jwks)
    assert decoded["sub"] == "jwks_kid_match"


def test_verify_using_jwks_dict_single_key_fallback(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "single_jwks_fallback"}, private_key=priv_key, key_id="unmatched-kid")
    jwks = jwks_document([(pub_key, "only-key", "RS256")])
    decoded = verify(token, public_key_or_jwks=jwks)
    assert decoded["sub"] == "single_jwks_fallback"


def test_verify_using_jwks_dict_ed25519_rfc8037(ed25519_keys):
    priv_key, pub_key = ed25519_keys
    token = issue({"sub": "ed25519_jwks_user"}, private_key=priv_key, alg="Ed25519", key_id="ed-key-99")
    jwks = jwks_document([(pub_key, "ed-key-99", "Ed25519")])
    decoded = verify(token, public_key_or_jwks=jwks)
    assert decoded["sub"] == "ed25519_jwks_user"


def test_verify_using_jwks_dict_missing_kid_fails(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "missing_kid"}, private_key=priv_key, key_id="wanted-kid")
    other_pub1 = rsa.generate_private_key(65537, 2048).public_key()
    other_pub2 = rsa.generate_private_key(65537, 2048).public_key()
    jwks = jwks_document([(other_pub1, "other-1", "RS256"), (other_pub2, "other-2", "RS256")])
    with pytest.raises(TokenError) as exc_info:
        verify(token, public_key_or_jwks=jwks)
    assert "unable to resolve verification key" in str(exc_info.value).lower()


# ==============================================================================
# SECTION 5: Key Rotation (rotate) & Cryptographic Independence (Tests 35 - 40)
# ==============================================================================

def test_rotate_returns_valid_rsa_keypair_and_kid():
    priv, pub, kid = rotate()
    assert isinstance(priv, rsa.RSAPrivateKey)
    assert isinstance(pub, rsa.RSAPublicKey)
    assert isinstance(kid, str)


def test_rotate_key_size_is_2048():
    priv, pub, _ = rotate()
    assert priv.key_size == 2048
    assert pub.key_size == 2048


def test_rotate_kid_format_and_uniqueness():
    _, _, kid1 = rotate()
    _, _, kid2 = rotate()
    assert kid1.startswith("key-")
    assert kid2.startswith("key-")
    assert kid1 != kid2


def test_tokens_issued_with_rotated_keys_verify_correctly():
    priv, pub, kid = rotate()
    token = issue({"sub": "rotated_user"}, private_key=priv, key_id=kid)
    decoded = verify(token, public_key_or_jwks=pub)
    assert decoded["sub"] == "rotated_user"


def test_multiple_rotations_produce_distinct_independent_keys():
    priv1, pub1, kid1 = rotate()
    priv2, pub2, kid2 = rotate()
    assert priv1.private_numbers().p != priv2.private_numbers().p
    assert pub1.public_numbers().n != pub2.public_numbers().n


def test_rotated_key_token_cannot_verify_with_old_key():
    priv1, pub1, kid1 = rotate()
    priv2, pub2, kid2 = rotate()
    token = issue({"sub": "isolated_key_user"}, private_key=priv1, key_id=kid1)
    with pytest.raises(TokenError):
        verify(token, public_key_or_jwks=pub2)


# ==============================================================================
# SECTION 6: Security Attacks, Tampering & Forgery Defenses (Tests 41 - 50)
# ==============================================================================

def test_signature_byte_tampering_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "legit_user"}, private_key=priv_key)
    header, payload, sig = token.split(".")
    # Tamper with the signature string
    tampered_sig = ("B" if sig[0] == "A" else "A") + sig[1:]
    tampered_token = f"{header}.{payload}.{tampered_sig}"
    with pytest.raises(TokenError) as exc_info:
        verify(tampered_token, public_key_or_jwks=pub_key)
    assert "signature verification failed" in str(exc_info.value).lower()


def test_signature_truncation_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "legit_user"}, private_key=priv_key)
    header, payload, sig = token.split(".")
    truncated_token = f"{header}.{payload}.{sig[:len(sig)//2]}"
    with pytest.raises(TokenError):
        verify(truncated_token, public_key_or_jwks=pub_key)


def test_signature_extension_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "legit_user"}, private_key=priv_key)
    extended_token = token + "extra_bytes"
    with pytest.raises(TokenError):
        verify(extended_token, public_key_or_jwks=pub_key)


def test_payload_claim_tampering_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "normal_user", "role": "viewer"}, private_key=priv_key)
    header, payload_b64, sig = token.split(".")
    # Decode payload, modify claim, and re-encode
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode("utf-8"))
    payload["role"] = "superadmin"
    tampered_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
    tampered_token = f"{header}.{tampered_payload_b64}.{sig}"
    with pytest.raises(TokenError) as exc_info:
        verify(tampered_token, public_key_or_jwks=pub_key)
    assert "signature verification failed" in str(exc_info.value).lower()


def test_payload_privilege_escalation_tampering_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"is_admin": False}, private_key=priv_key)
    header, payload_b64, sig = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode("utf-8"))
    payload["is_admin"] = True
    tampered_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
    with pytest.raises(TokenError):
        verify(f"{header}.{tampered_payload_b64}.{sig}", public_key_or_jwks=pub_key)


def test_payload_expiry_extension_tampering_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "expired_user"}, private_key=priv_key, ttl_seconds=-10)
    header, payload_b64, sig = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode("utf-8"))
    payload["exp"] = int(time.time()) + 100000  # Try to prolong expired token
    tampered_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
    with pytest.raises(TokenError):
        verify(f"{header}.{tampered_payload_b64}.{sig}", public_key_or_jwks=pub_key)


def test_header_alg_none_attack_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "none_attack"}, private_key=priv_key)
    _, payload, sig = token.split(".")
    fake_header = {"alg": "none", "typ": "JWT"}
    fake_header_b64 = base64.urlsafe_b64encode(json.dumps(fake_header).encode("utf-8")).decode("ascii").rstrip("=")
    attack_token = f"{fake_header_b64}.{payload}.{sig}"
    with pytest.raises(TokenError) as exc_info:
        verify(attack_token, public_key_or_jwks=pub_key)
    assert "allowlist check failed" in str(exc_info.value).lower()


def test_header_alg_hs256_confusion_attack_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "hs256_attack"}, private_key=priv_key)
    _, payload, sig = token.split(".")
    fake_header = {"alg": "HS256", "typ": "JWT"}
    fake_header_b64 = base64.urlsafe_b64encode(json.dumps(fake_header).encode("utf-8")).decode("ascii").rstrip("=")
    attack_token = f"{fake_header_b64}.{payload}.{sig}"
    with pytest.raises(TokenError) as exc_info:
        verify(attack_token, public_key_or_jwks=pub_key)
    assert "allowlist check failed" in str(exc_info.value).lower()


def test_disallowed_alg_in_issue_rejected(rsa_keys):
    priv_key, _ = rsa_keys
    bad_algorithms = ["none", "HS256", "ES256", "RS384", "INVALID_CIPHER"]
    for bad_alg in bad_algorithms:
        with pytest.raises(TokenError) as exc_info:
            issue({"sub": "bad_alg_user"}, private_key=priv_key, alg=bad_alg)
        assert "allowlist check failed" in str(exc_info.value).lower()


def test_cross_key_forgery_rejection(rsa_keys):
    priv1, pub1 = rsa_keys
    priv2, pub2 = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048).public_key()
    token = issue({"sub": "key1_user"}, private_key=priv1)
    with pytest.raises(TokenError):
        verify(token, public_key_or_jwks=pub2)


# ==============================================================================
# SECTION 7: Malformed Inputs & Edge Case Rejections (Tests 51 - 58)
# ==============================================================================

def test_non_string_token_types_rejected(rsa_keys):
    _, pub_key = rsa_keys
    invalid_types = [12345, None, ["token"], {"token": "jwt"}, b"bytes_token", 3.14]
    for bad_val in invalid_types:
        with pytest.raises(TokenError) as exc_info:
            verify(bad_val, public_key_or_jwks=pub_key)
        assert "must be str" in str(exc_info.value).lower()


def test_empty_string_token_rejected(rsa_keys):
    _, pub_key = rsa_keys
    with pytest.raises(TokenError) as exc_info:
        verify("", public_key_or_jwks=pub_key)
    assert "invalid jwt token format" in str(exc_info.value).lower()


def test_token_missing_dots_rejected(rsa_keys):
    _, pub_key = rsa_keys
    with pytest.raises(TokenError):
        verify("headerpayloadsignature", public_key_or_jwks=pub_key)


def test_token_one_dot_rejected(rsa_keys):
    _, pub_key = rsa_keys
    with pytest.raises(TokenError):
        verify("header.payload", public_key_or_jwks=pub_key)


def test_token_too_many_dots_rejected(rsa_keys):
    _, pub_key = rsa_keys
    with pytest.raises(TokenError):
        verify("part1.part2.part3.part4", public_key_or_jwks=pub_key)


def test_token_only_dots_rejected(rsa_keys):
    _, pub_key = rsa_keys
    with pytest.raises(TokenError):
        verify("..", public_key_or_jwks=pub_key)


def test_corrupted_base64_header_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "user"}, private_key=priv_key)
    _, payload, sig = token.split(".")
    bad_header_token = f"???invalid_b64???_{payload}.{sig}"
    with pytest.raises(TokenError):
        verify(bad_header_token, public_key_or_jwks=pub_key)


def test_corrupted_base64_payload_rejected(rsa_keys):
    priv_key, pub_key = rsa_keys
    token = issue({"sub": "user"}, private_key=priv_key)
    header, _, sig = token.split(".")
    bad_payload_token = f"{header}.???invalid_b64???.{sig}"
    with pytest.raises(TokenError):
        verify(bad_payload_token, public_key_or_jwks=pub_key)


# ==============================================================================
# SECTION 8: Multilingual, Unicode, Emojis & Stress Testing (Tests 59 - 62)
# ==============================================================================

def test_unicode_and_multilingual_claims_preservation(rsa_keys):
    priv_key, pub_key = rsa_keys
    claims = {
        "hindi_name": "यश कुमार",
        "japanese": "セキュアトークン",
        "arabic": "أمان النظام",
        "european": "Hélène Müller François",
    }
    token = issue(claims, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key)
    for k, v in claims.items():
        assert decoded[k] == v


def test_special_characters_and_emojis_in_claims(rsa_keys):
    priv_key, pub_key = rsa_keys
    claims = {
        "security_badge": "🛡️🔑⚡",
        "email_with_plus": "security+vault.test@sub.domain.corp",
        "sql_chars": "SELECT * FROM users WHERE '1'='1';",
        "quotes": 'Quote: "Safe" & \'Secure\'',
    }
    token = issue(claims, private_key=priv_key)
    decoded = verify(token, public_key_or_jwks=pub_key)
    for k, v in claims.items():
        assert decoded[k] == v


def test_high_volume_batch_issuance_and_verification(rsa_keys):
    priv_key, pub_key = rsa_keys
    count = 50
    t0 = time.time()
    tokens = [issue({"batch_idx": i, "sub": f"user_{i}"}, private_key=priv_key) for i in range(count)]
    t_issue = time.time() - t0

    t0 = time.time()
    for idx, tok in enumerate(tokens):
        decoded = verify(tok, public_key_or_jwks=pub_key)
        assert decoded["batch_idx"] == idx
    t_verify = time.time() - t0

    assert len(tokens) == count
    # Performance assertion: 50 token issues and 50 verifications must be under 3 seconds
    assert (t_issue + t_verify) < 3.0


def test_batch_jti_uniqueness_guarantee(rsa_keys):
    priv_key, pub_key = rsa_keys
    count = 50
    tokens = [issue({"sub": "same_user"}, private_key=priv_key) for _ in range(count)]
    jtis = set()
    for tok in tokens:
        decoded = verify(tok, public_key_or_jwks=pub_key)
        jtis.add(decoded["jti"])
    assert len(jtis) == count  # Zero collisions among 50 generated tokens
