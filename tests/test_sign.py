"""
Comprehensive End-to-End Test Suite for osivault.sign module.
Covers 50+ rigorous test cases spanning:
1. RS256 (RSA-2048 PKCS1v15 + SHA-256) Signature & Verification Roundtrips
2. Ed25519 (High-Speed Pure Edwards Curve) Signature & Verification Roundtrips
3. Envelope Format Conformance & Self-Describing Metadata (OSV1-SIG$... format)
4. Dynamic Key Resolution (key_resolver callback vs direct public_key)
5. Cryptographic Tampering Defenses (Payload modification, Signature flipping, Truncation)
6. Strict Allowlist-First Defense (Disallowed algs: none, HS256, MD5, arbitrary strings)
7. Malformed Envelope Handling (Corrupted Base64, Missing $, Bad Header Prefix)
8. Multilingual, Binary, PDF, Special Delimiter Payloads & Stress Loop
"""

import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from osivault.sign import (
    sign,
    verify,
    Envelope,
    SignatureVerificationError,
    ALLOWED_SIGNATURE_ALGORITHMS,
    SIG_HEADER_PREFIX,
)


@pytest.fixture
def rsa_keys():
    """Generates standard 2048-bit RSA keypair."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def ed25519_keys():
    """Generates standard Ed25519 keypair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


# ==============================================================================
# SECTION 1: RS256 Signing and Verification Roundtrips (Tests 1 - 8)
# ==============================================================================

def test_rsa_bytes_payload_roundtrip(rsa_keys):
    priv, pub = rsa_keys
    payload = b"OSIVault Audit Checkpoint Data #42"
    env_str = sign(payload, key=priv, alg="RS256", key_id="rsa-k1")
    env = verify(env_str, public_key=pub)
    assert isinstance(env, Envelope)
    assert env.sig_alg == "RS256"
    assert env.key_id == "rsa-k1"
    assert env.payload == payload
    assert len(env.signature) > 0


def test_rsa_string_payload_roundtrip(rsa_keys):
    priv, pub = rsa_keys
    payload = "Text string payload to sign"
    env_str = sign(payload, key=priv, alg="RS256")
    env = verify(env_str, public_key=pub)
    assert env.payload == payload.encode("utf-8")


def test_rsa_empty_bytes_payload(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"", key=priv, alg="RS256")
    env = verify(env_str, public_key=pub)
    assert env.payload == b""


def test_rsa_default_key_id(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"default_kid_test", key=priv, alg="RS256")
    env = verify(env_str, public_key=pub)
    assert env.key_id == "default"


def test_rsa_custom_key_id(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"custom_kid", key=priv, alg="RS256", key_id="vault-prod-key-99")
    env = verify(env_str, public_key=pub)
    assert env.key_id == "vault-prod-key-99"


def test_rsa_large_payload(rsa_keys):
    priv, pub = rsa_keys
    large_payload = b"A" * 100000  # 100 KB
    env_str = sign(large_payload, key=priv, alg="RS256")
    env = verify(env_str, public_key=pub)
    assert env.payload == large_payload


def test_rsa_key_resolver_callback(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"resolver_test", key=priv, alg="RS256", key_id="client-rsa-key")
    env = verify(env_str, key_resolver=lambda kid: pub if kid == "client-rsa-key" else None)
    assert env.payload == b"resolver_test"


def test_rsa_envelope_header_prefix(rsa_keys):
    priv, _ = rsa_keys
    env_str = sign(b"check_prefix", key=priv, alg="RS256")
    assert env_str.startswith(SIG_HEADER_PREFIX)


# ==============================================================================
# SECTION 2: Ed25519 Signing and Verification Roundtrips (Tests 9 - 16)
# ==============================================================================

def test_ed25519_bytes_payload_roundtrip(ed25519_keys):
    priv, pub = ed25519_keys
    payload = b"Pure Ed25519 High Speed Signature"
    env_str = sign(payload, key=priv, alg="Ed25519", key_id="ed-k1")
    env = verify(env_str, public_key=pub)
    assert isinstance(env, Envelope)
    assert env.sig_alg == "Ed25519"
    assert env.key_id == "ed-k1"
    assert env.payload == payload
    assert len(env.signature) == 64  # Ed25519 signature is always 64 bytes


def test_ed25519_string_payload_roundtrip(ed25519_keys):
    priv, pub = ed25519_keys
    payload = "Ed25519 text payload"
    env_str = sign(payload, key=priv, alg="Ed25519")
    env = verify(env_str, public_key=pub)
    assert env.payload == payload.encode("utf-8")


def test_ed25519_empty_payload(ed25519_keys):
    priv, pub = ed25519_keys
    env_str = sign(b"", key=priv, alg="Ed25519")
    env = verify(env_str, public_key=pub)
    assert env.payload == b""


def test_ed25519_custom_key_id(ed25519_keys):
    priv, pub = ed25519_keys
    env_str = sign(b"ed_kid", key=priv, alg="Ed25519", key_id="ed-vault-007")
    env = verify(env_str, public_key=pub)
    assert env.key_id == "ed-vault-007"


def test_ed25519_large_payload(ed25519_keys):
    priv, pub = ed25519_keys
    large_payload = b"E" * 150000
    env_str = sign(large_payload, key=priv, alg="Ed25519")
    env = verify(env_str, public_key=pub)
    assert env.payload == large_payload


def test_ed25519_key_resolver_callback(ed25519_keys):
    priv, pub = ed25519_keys
    env_str = sign(b"ed_resolver", key=priv, alg="Ed25519", key_id="ed-resolver-id")
    env = verify(env_str, key_resolver=lambda kid: pub if kid == "ed-resolver-id" else None)
    assert env.payload == b"ed_resolver"


def test_ed25519_envelope_hash_alg_preserved(ed25519_keys):
    priv, pub = ed25519_keys
    env_str = sign(b"test_hash", key=priv, alg="Ed25519", hash_alg="SHA256")
    env = verify(env_str, public_key=pub)
    assert env.hash_alg == "SHA256"


def test_ed25519_envelope_format_version(ed25519_keys):
    priv, pub = ed25519_keys
    env_str = sign(b"test_ver", key=priv, alg="Ed25519")
    env = verify(env_str, public_key=pub)
    assert env.fmt_ver == 1


# ==============================================================================
# SECTION 3: Envelope Format & Metadata Conformance (Tests 17 - 22)
# ==============================================================================

def test_envelope_six_part_delimiter_structure(rsa_keys):
    priv, _ = rsa_keys
    env_str = sign(b"delimiter_check", key=priv, alg="RS256", key_id="k-1")
    parts = env_str.split("$")
    assert len(parts) == 6
    assert parts[0] == "OSV1-SIG"
    assert parts[1] == "RS256"
    assert parts[2] == "k-1"
    assert parts[3] == "SHA256"


def test_envelope_base64_payload_unpadded(rsa_keys):
    priv, _ = rsa_keys
    env_str = sign(b"unpadded_check", key=priv)
    parts = env_str.split("$")
    payload_b64 = parts[4]
    sig_b64 = parts[5]
    assert "=" not in payload_b64
    assert "=" not in sig_b64


def test_envelope_dataclass_fields(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"dc_test", key=priv, key_id="my-id")
    env = verify(env_str, public_key=pub)
    assert hasattr(env, "sig_alg")
    assert hasattr(env, "fmt_ver")
    assert hasattr(env, "hash_alg")
    assert hasattr(env, "key_id")
    assert hasattr(env, "payload")
    assert hasattr(env, "signature")


def test_allowed_algorithms_constant():
    assert "RS256" in ALLOWED_SIGNATURE_ALGORITHMS
    assert "Ed25519" in ALLOWED_SIGNATURE_ALGORITHMS
    assert len(ALLOWED_SIGNATURE_ALGORITHMS) == 2


def test_sig_header_prefix_constant():
    assert SIG_HEADER_PREFIX == "OSV1-SIG"


def test_envelope_string_representation(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"repr_check", key=priv)
    env = verify(env_str, public_key=pub)
    assert "Envelope" in repr(env)


# ==============================================================================
# SECTION 4: Cryptographic Tampering & Forgery Defenses (Tests 23 - 32)
# ==============================================================================

def test_tampered_payload_byte_rejected(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"Original Statement", key=priv)
    parts = env_str.split("$")
    # Tamper with base64 payload
    payload_b64 = parts[4]
    tampered_b64 = ("A" if payload_b64[0] != "A" else "B") + payload_b64[1:]
    parts[4] = tampered_b64
    with pytest.raises(SignatureVerificationError) as exc_info:
        verify("$".join(parts), public_key=pub)
    assert "verification failed" in str(exc_info.value).lower()


def test_tampered_signature_byte_rejected(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"Authentic Data", key=priv)
    parts = env_str.split("$")
    sig_b64 = parts[5]
    tampered_sig = ("B" if sig_b64[10] != "B" else "A") + sig_b64[1:]
    parts[5] = tampered_sig
    with pytest.raises(SignatureVerificationError) as exc_info:
        verify("$".join(parts), public_key=pub)
    assert "verification failed" in str(exc_info.value).lower()


def test_truncated_signature_rejected(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"Data", key=priv)
    parts = env_str.split("$")
    parts[5] = parts[5][:len(parts[5]) // 2]
    with pytest.raises(SignatureVerificationError):
        verify("$".join(parts), public_key=pub)


def test_extended_signature_rejected(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"Data", key=priv)
    parts = env_str.split("$")
    parts[5] = parts[5] + "extrabytes"
    with pytest.raises(SignatureVerificationError):
        verify("$".join(parts), public_key=pub)


def test_tampered_ed25519_signature_rejected(ed25519_keys):
    priv, pub = ed25519_keys
    env_str = sign(b"Ed25519 Authentic", key=priv, alg="Ed25519")
    parts = env_str.split("$")
    sig = parts[5]
    parts[5] = ("X" if sig[5] != "X" else "Y") + sig[1:]
    with pytest.raises(SignatureVerificationError):
        verify("$".join(parts), public_key=pub)


def test_tampered_ed25519_payload_rejected(ed25519_keys):
    priv, pub = ed25519_keys
    env_str = sign(b"Ed25519 Data", key=priv, alg="Ed25519")
    parts = env_str.split("$")
    parts[4] = base64.urlsafe_b64encode(b"Tampered Data").decode("ascii").rstrip("=")
    with pytest.raises(SignatureVerificationError):
        verify("$".join(parts), public_key=pub)


def test_cross_key_rsa_forgery_rejected(rsa_keys):
    priv1, _ = rsa_keys
    other_priv = rsa.generate_private_key(65537, 2048)
    other_pub = other_priv.public_key()
    env_str = sign(b"Secret Document", key=priv1)
    with pytest.raises(SignatureVerificationError):
        verify(env_str, public_key=other_pub)


def test_cross_key_ed25519_forgery_rejected(ed25519_keys):
    priv1, _ = ed25519_keys
    other_priv = ed25519.Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key()
    env_str = sign(b"Secret Ed Document", key=priv1, alg="Ed25519")
    with pytest.raises(SignatureVerificationError):
        verify(env_str, public_key=other_pub)


def test_rsa_key_with_ed25519_alg_type_error(rsa_keys):
    priv, _ = rsa_keys
    with pytest.raises(TypeError, match="Ed25519 requires"):
        sign(b"data", key=priv, alg="Ed25519")


def test_ed25519_key_with_rsa_alg_type_error(ed25519_keys):
    priv, _ = ed25519_keys
    with pytest.raises(TypeError, match="RS256 requires"):
        sign(b"data", key=priv, alg="RS256")


# ==============================================================================
# SECTION 5: Allowlist-First Algorithm Security (Tests 33 - 40)
# ==============================================================================

def test_sign_disallowed_alg_none(rsa_keys):
    priv, _ = rsa_keys
    with pytest.raises(SignatureVerificationError) as exc_info:
        sign(b"data", key=priv, alg="none")
    assert "allowlist check failed" in str(exc_info.value).lower()


def test_sign_disallowed_alg_hs256(rsa_keys):
    priv, _ = rsa_keys
    with pytest.raises(SignatureVerificationError) as exc_info:
        sign(b"data", key=priv, alg="HS256")
    assert "allowlist check failed" in str(exc_info.value).lower()


def test_sign_disallowed_alg_md5(rsa_keys):
    priv, _ = rsa_keys
    with pytest.raises(SignatureVerificationError):
        sign(b"data", key=priv, alg="MD5withRSA")


def test_sign_disallowed_alg_arbitrary_string(rsa_keys):
    priv, _ = rsa_keys
    with pytest.raises(SignatureVerificationError):
        sign(b"data", key=priv, alg="SUPER_CIPHER_1000")


def test_verify_disallowed_alg_none(rsa_keys):
    _, pub = rsa_keys
    fake_envelope = "OSV1-SIG$none$default$SHA256$dGVzdA$ZmFrZXNpZw"
    with pytest.raises(SignatureVerificationError) as exc_info:
        verify(fake_envelope, public_key=pub)
    assert "allowlist check failed" in str(exc_info.value).lower()


def test_verify_disallowed_alg_hs256(rsa_keys):
    _, pub = rsa_keys
    fake_envelope = "OSV1-SIG$HS256$default$SHA256$dGVzdA$ZmFrZXNpZw"
    with pytest.raises(SignatureVerificationError) as exc_info:
        verify(fake_envelope, public_key=pub)
    assert "allowlist check failed" in str(exc_info.value).lower()


def test_verify_disallowed_alg_md5(rsa_keys):
    _, pub = rsa_keys
    fake_envelope = "OSV1-SIG$MD5$default$SHA256$dGVzdA$ZmFrZXNpZw"
    with pytest.raises(SignatureVerificationError):
        verify(fake_envelope, public_key=pub)


def test_verify_disallowed_alg_case_sensitivity(rsa_keys):
    _, pub = rsa_keys
    fake_envelope = "OSV1-SIG$rs256$default$SHA256$dGVzdA$ZmFrZXNpZw"
    with pytest.raises(SignatureVerificationError):
        verify(fake_envelope, public_key=pub)


# ==============================================================================
# SECTION 6: Key Resolution Workflows (Tests 41 - 46)
# ==============================================================================

def test_no_key_and_no_resolver_raises_error(rsa_keys):
    priv, _ = rsa_keys
    env_str = sign(b"no_key_test", key=priv)
    with pytest.raises(SignatureVerificationError, match="No public key available"):
        verify(env_str, public_key=None, key_resolver=None)


def test_resolver_returns_none_raises_error(rsa_keys):
    priv, _ = rsa_keys
    env_str = sign(b"test", key=priv, key_id="unknown-kid")
    with pytest.raises(SignatureVerificationError, match="No public key available"):
        verify(env_str, key_resolver=lambda kid: None)


def test_direct_public_key_overrides_resolver(rsa_keys):
    priv, pub = rsa_keys
    other_pub = rsa.generate_private_key(65537, 2048).public_key()
    env_str = sign(b"test_override", key=priv)
    # Resolver returns wrong key, but direct public_key is right key
    env = verify(env_str, public_key=pub, key_resolver=lambda kid: other_pub)
    assert env.payload == b"test_override"


def test_multi_key_resolver_routing(rsa_keys, ed25519_keys):
    rsa_priv, rsa_pub = rsa_keys
    ed_priv, ed_pub = ed25519_keys

    key_store = {
        "rsa-client": rsa_pub,
        "ed-client": ed_pub,
    }
    resolver = lambda kid: key_store.get(kid)

    env_rsa = sign(b"rsa_doc", key=rsa_priv, alg="RS256", key_id="rsa-client")
    env_ed = sign(b"ed_doc", key=ed_priv, alg="Ed25519", key_id="ed-client")

    res_rsa = verify(env_rsa, key_resolver=resolver)
    res_ed = verify(env_ed, key_resolver=resolver)

    assert res_rsa.payload == b"rsa_doc"
    assert res_ed.payload == b"ed_doc"


def test_wrong_key_type_in_verify_rsa(ed25519_keys):
    _, ed_pub = ed25519_keys
    fake_envelope = "OSV1-SIG$RS256$default$SHA256$dGVzdA$c2ln"
    with pytest.raises((SignatureVerificationError, TypeError)):
        verify(fake_envelope, public_key=ed_pub)


def test_wrong_key_type_in_verify_ed25519(rsa_keys):
    _, rsa_pub = rsa_keys
    fake_envelope = "OSV1-SIG$Ed25519$default$SHA256$dGVzdA$c2ln"
    with pytest.raises((SignatureVerificationError, TypeError)):
        verify(fake_envelope, public_key=rsa_pub)


# ==============================================================================
# SECTION 7: Malformed Inputs & Edge Cases (Tests 47 - 54)
# ==============================================================================

def test_non_string_envelope_raises_error():
    for bad_input in [123, None, [1, 2], {"env": "str"}, b"bytes_env"]:
        with pytest.raises(SignatureVerificationError, match="Envelope must be str"):
            verify(bad_input, public_key=None)


def test_non_string_payload_sign_raises_type_error(rsa_keys):
    priv, _ = rsa_keys
    for bad_input in [123, None, [1, 2], {"key": "val"}]:
        with pytest.raises(TypeError, match="Payload must be bytes or str"):
            sign(bad_input, key=priv)


def test_empty_string_envelope_raises_error(rsa_keys):
    _, pub = rsa_keys
    with pytest.raises(SignatureVerificationError, match="Invalid signature envelope"):
        verify("", public_key=pub)


def test_missing_osv1_sig_prefix(rsa_keys):
    _, pub = rsa_keys
    bad_prefix = "INVALID-SIG$RS256$default$SHA256$dGVzdA$c2ln"
    with pytest.raises(SignatureVerificationError, match="Invalid signature envelope"):
        verify(bad_prefix, public_key=pub)


def test_fewer_than_six_parts(rsa_keys):
    _, pub = rsa_keys
    short_env = "OSV1-SIG$RS256$default$SHA256$dGVzdA"
    with pytest.raises(SignatureVerificationError, match="Invalid signature envelope"):
        verify(short_env, public_key=pub)


def test_corrupted_base64_payload_string(rsa_keys):
    _, pub = rsa_keys
    bad_b64 = "OSV1-SIG$RS256$default$SHA256$???invalid_b64???$c2ln"
    with pytest.raises(SignatureVerificationError):
        verify(bad_b64, public_key=pub)


def test_corrupted_base64_signature_string(rsa_keys):
    _, pub = rsa_keys
    bad_sig_b64 = "OSV1-SIG$RS256$default$SHA256$dGVzdA$???invalid_sig_b64???"
    with pytest.raises(SignatureVerificationError):
        verify(bad_sig_b64, public_key=pub)


def test_envelope_with_extra_empty_parts(rsa_keys):
    priv, pub = rsa_keys
    env_str = sign(b"extra_dollar", key=priv)
    broken_str = env_str + "$extrastring"
    # Even if split gives > 6, verify parses first 6 parts and validates signature
    env = verify(broken_str, public_key=pub)
    assert env.payload == b"extra_dollar"


# ==============================================================================
# SECTION 8: Multilingual, Binary, Special Characters & Stress Loop (Tests 55 - 58)
# ==============================================================================

def test_unicode_multilingual_payload_signing(rsa_keys):
    priv, pub = rsa_keys
    multilingual = "डिजिटल हस्ताक्षर | 電子署名 | التوقيع الرقمي | Signature Numérique"
    env_str = sign(multilingual, key=priv, alg="RS256")
    env = verify(env_str, public_key=pub)
    assert env.payload.decode("utf-8") == multilingual


def test_binary_file_payload_pdf_png_signing(ed25519_keys):
    priv, pub = ed25519_keys
    # Synthetic PDF header & PNG magic bytes
    binary_content = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n" + b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    env_str = sign(binary_content, key=priv, alg="Ed25519")
    env = verify(env_str, public_key=pub)
    assert env.payload == binary_content


def test_payload_with_dollar_and_special_delimiters(rsa_keys):
    priv, pub = rsa_keys
    tricky_payload = b"Price=$100$$$Delimiter~*|:\x00\xffSpecial"
    env_str = sign(tricky_payload, key=priv, alg="RS256")
    env = verify(env_str, public_key=pub)
    assert env.payload == tricky_payload


def test_batch_signing_stress_loop(ed25519_keys):
    priv, pub = ed25519_keys
    count = 50
    envelopes = []
    for i in range(count):
        payload = f"EDI_BATCH_CLAIM_TRANSACTION_ID_{i}".encode("utf-8")
        env_str = sign(payload, key=priv, alg="Ed25519", key_id=f"kid-{i}")
        envelopes.append((payload, env_str))

    assert len(envelopes) == count
    for expected_payload, env_str in envelopes:
        env = verify(env_str, public_key=pub)
        assert env.payload == expected_payload
