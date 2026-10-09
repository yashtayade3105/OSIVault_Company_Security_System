"""
Tests for osivault.fields module.
Covers AES-256-GCM encryption, fresh DEK generation, context (AAD) binding,
allowlist-first self-describing header verification, DEK rotation, SearchHash blind indexing,
and Django EncryptedTextField / EncryptedJSONField.
"""

import os
import pytest

pytestmark = pytest.mark.django_db
from django.db import models
from osivault.fields import (
    encrypt,
    decrypt,
    rotate_dek,
    SearchHash,
    EncryptedTextField,
    EncryptedJSONField,
)
from osivault.fields.crypto import FieldEncryptionError


def test_encrypt_decrypt_basic_roundtrip():
    """Test basic string and bytes encryption and decryption."""
    plaintext = "Patient John Doe SSN: 123-45-6789"
    key = os.urandom(32)
    
    ciphertext = encrypt(plaintext, key=key)
    assert ciphertext != plaintext
    assert ciphertext.startswith("OSV1$AES-256-GCM$") or "OSV1" in ciphertext
    
    decrypted = decrypt(ciphertext, key=key)
    assert decrypted == plaintext


def test_context_aad_binding():
    """Test that context (AAD) mismatch causes decryption authentication failure."""
    plaintext = "Sensitive PHI Record"
    key = os.urandom(32)
    context_correct = "tenant_101:patient_999"
    context_wrong = "tenant_101:patient_888"

    ciphertext = encrypt(plaintext, key=key, context=context_correct)

    # Decrypting with wrong context must fail
    with pytest.raises(FieldEncryptionError):
        decrypt(ciphertext, key=key, context=context_wrong)

    # Decrypting with correct context succeeds
    assert decrypt(ciphertext, key=key, context=context_correct) == plaintext


def test_fresh_dek_randomness():
    """Test that encrypting the same text twice generates different ciphertexts (fresh DEK & IV)."""
    plaintext = "Identical Input Text"
    key = os.urandom(32)

    ct1 = encrypt(plaintext, key=key)
    ct2 = encrypt(plaintext, key=key)

    assert ct1 != ct2
    assert decrypt(ct1, key=key) == plaintext
    assert decrypt(ct2, key=key) == plaintext


def test_allowlist_header_rejection():
    """Test that ciphertext with non-allowlisted algorithm header is rejected before crypto ops."""
    key = os.urandom(32)
    # Fabricate envelope with disallowed algorithm
    bad_envelope = "OSV1$DES-CBC$kid=default$iv=12345678$payload=abcdef"

    with pytest.raises(FieldEncryptionError) as exc_info:
        decrypt(bad_envelope, key=key)
    assert "Allowlist" in str(exc_info.value) or "disallowed" in str(exc_info.value).lower() or "unsupported" in str(exc_info.value).lower()


def test_tampered_ciphertext_detection():
    """Test that tampered ciphertext or MAC tag causes decryption failure."""
    plaintext = "Confidential Claim Data"
    key = os.urandom(32)

    ciphertext = encrypt(plaintext, key=key)
    # Corrupt last character of ciphertext envelope
    corrupted = ciphertext[:-2] + ("0" if ciphertext[-1] != "0" else "1")

    with pytest.raises(FieldEncryptionError):
        decrypt(corrupted, key=key)


def test_rotate_dek():
    """Test re-encrypting ciphertext envelope under new key or fresh DEK."""
    plaintext = "Data to be re-keyed"
    old_key = os.urandom(32)
    new_key = os.urandom(32)

    ct_old = encrypt(plaintext, key=old_key)
    ct_new = rotate_dek(ct_old, new_key=new_key, old_key=old_key)

    assert ct_old != ct_new
    # Old key fails on new ciphertext
    with pytest.raises(FieldEncryptionError):
        decrypt(ct_new, key=old_key)

    # New key decrypts new ciphertext
    assert decrypt(ct_new, key=new_key) == plaintext


def test_search_hash_blind_index():
    """Test SearchHash deterministic blind index hashing for querying encrypted fields."""
    ssn = "123-45-6789"
    salt = "system-blind-index-salt-2026"

    hash1 = SearchHash(ssn, salt=salt)
    hash2 = SearchHash(ssn, salt=salt)
    hash_diff_salt = SearchHash(ssn, salt="different-salt")

    assert hash1 == hash2
    assert hash1 != ssn
    assert hash1 != hash_diff_salt
    assert len(hash1) == 64  # SHA-256 hex string


def test_django_encrypted_fields():
    """Test EncryptedTextField and EncryptedJSONField model integration."""
    from tests.models import PatientRecord

    record = PatientRecord.objects.create(
        patient_name="Alice Smith",
        ssn="987-65-4321",
        ssn_search=SearchHash("987-65-4321"),
        medical_history={"allergies": ["Penicillin"], "blood_type": "O+"},
    )

    # Query from DB
    retrieved = PatientRecord.objects.get(id=record.id)
    assert retrieved.patient_name == "Alice Smith"
    assert retrieved.ssn == "987-65-4321"
    assert retrieved.medical_history == {"allergies": ["Penicillin"], "blood_type": "O+"}

    # Query using SearchHash
    queried = PatientRecord.objects.get(ssn_search=SearchHash("987-65-4321"))
    assert queried.id == record.id


def test_unicode_and_emoji_field_encryption():
    """Test encrypting and decrypting UTF-8 multi-language text, emojis, and special control chars."""
    unicode_text = "yash_tayade_🚀_सुरक्षा_🔐_日本語_Österreich_@#$^&*()'\"\\\n\t"
    key = os.urandom(32)

    ciphertext = encrypt(unicode_text, key=key)
    assert ciphertext != unicode_text
    assert decrypt(ciphertext, key=key) == unicode_text


def test_empty_string_and_null_field_handling():
    """Test encrypting and decrypting empty strings, and handling None values in model fields."""
    key = os.urandom(32)

    # Empty string encrypt/decrypt
    ct_empty = encrypt("", key=key)
    assert decrypt(ct_empty, key=key) == ""

    # Model fields null & empty string roundtrip
    from tests.models import PatientRecord

    rec1 = PatientRecord.objects.create(
        patient_name="Null Patient",
        ssn=None,
        secret_code="",
        medical_history=None,
    )
    fetched1 = PatientRecord.objects.get(id=rec1.id)
    assert fetched1.ssn is None
    assert fetched1.secret_code == "" or fetched1.secret_code is None
    assert fetched1.medical_history is None


def test_large_payload_encryption():
    """Test encrypting and decrypting large 1 MB string payloads."""
    large_text = "A" * (1024 * 1024)  # 1 MB string
    key = os.urandom(32)

    ciphertext = encrypt(large_text, key=key)
    assert decrypt(ciphertext, key=key) == large_text


def test_kms_local_keyring_provider_variations(monkeypatch):
    """Test LocalKeyringProvider key formatting, fallbacks, and production fail-closed safety."""
    from osivault.fields.kms import LocalKeyringProvider

    # 1. 32-byte raw bytes
    raw_key = b"01234567890123456789012345678901"
    provider1 = LocalKeyringProvider(fallback_key=raw_key)
    assert provider1.get_master_key() == raw_key

    # 2. Plaintext string auto-formatted to 32 bytes
    provider2 = LocalKeyringProvider(fallback_key="short_key")
    assert len(provider2.get_master_key()) == 32

    # 3. Environment variable key resolution
    monkeypatch.setenv("OSIVAULT_FIELD_KEY", "env_master_key_32_bytes_secret!")
    provider3 = LocalKeyringProvider()
    assert len(provider3.get_master_key()) == 32

    # 4. Fail-closed in Production environment if OSIVAULT_FIELD_KEY is missing
    monkeypatch.delenv("OSIVAULT_FIELD_KEY", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")
    provider_prod = LocalKeyringProvider()
    with pytest.raises(ValueError, match="OSIVAULT_FIELD_KEY environment variable is missing"):
        provider_prod.get_master_key()


def test_invalid_ciphertext_envelope_variations():
    """Test error handling for non-string, invalid prefix, and corrupted base64 envelopes."""
    key = os.urandom(32)

    # 1. Non-string input
    with pytest.raises(FieldEncryptionError, match="Ciphertext envelope must be str"):
        decrypt(12345, key=key)

    # 2. Invalid envelope header format
    with pytest.raises(FieldEncryptionError, match="Invalid field encryption envelope header format"):
        decrypt("INVALID_PREFIX$AES-256-GCM$default$payload", key=key)

    with pytest.raises(FieldEncryptionError, match="Invalid field encryption envelope header format"):
        decrypt("OSV1$AES-256-GCM", key=key)

    # 3. Malformed Base64 envelope payload
    bad_b64_env = "OSV1$AES-256-GCM$default$NOT_VALID_BASE64_PAYLOAD!!!"
    with pytest.raises(FieldEncryptionError, match="Corrupted ciphertext"):
        decrypt(bad_b64_env, key=key)


def test_encrypt_invalid_type_raises():
    """Test passing non-string and non-bytes types to encrypt raises TypeError."""
    with pytest.raises(TypeError, match="Plaintext must be str or bytes"):
        encrypt(12345)

    with pytest.raises(TypeError, match="Plaintext must be str or bytes"):
        encrypt({"key": "value"})


def test_context_aad_empty_vs_none_vs_custom():
    """Test encrypting with context=None vs context='' vs context='custom'."""
    key = os.urandom(32)
    text = "AAD Test Text"

    ct_none = encrypt(text, key=key, context=None)
    ct_empty = encrypt(text, key=key, context="")
    ct_custom = encrypt(text, key=key, context="tenant:alpha")

    # None and empty string act equivalently
    assert decrypt(ct_none, key=key, context=None) == text
    assert decrypt(ct_empty, key=key, context=None) == text

    # Custom context decrypts with exact match
    assert decrypt(ct_custom, key=key, context="tenant:alpha") == text
    # Wrong context fails
    with pytest.raises(FieldEncryptionError):
        decrypt(ct_custom, key=key, context="tenant:beta")


def test_encrypted_json_field_nested_types():
    """Test EncryptedJSONField with dicts, lists, numbers, booleans, primitives, and empty containers."""
    from tests.models import PatientRecord

    complex_json = {
        "dict_key": {"sub_key": 100},
        "list_key": [1, 2, "three", True, None],
        "number": 99.95,
        "bool": True,
        "empty_dict": {},
        "empty_list": [],
    }

    rec = PatientRecord.objects.create(
        patient_name="Bob Test",
        medical_history=complex_json,
    )

    fetched = PatientRecord.objects.get(id=rec.id)
    assert fetched.medical_history == complex_json
    assert isinstance(fetched.medical_history["list_key"], list)
    assert fetched.medical_history["bool"] is True


def test_encrypted_char_field_integration():
    """Test EncryptedCharField model integration and long text handling."""
    from tests.models import PatientRecord

    rec = PatientRecord.objects.create(
        patient_name="Charlie Test",
        secret_code="TOP_SECRET_SECURITY_CODE_2026_VERY_LONG_STRING",
    )

    fetched = PatientRecord.objects.get(id=rec.id)
    assert fetched.secret_code == "TOP_SECRET_SECURITY_CODE_2026_VERY_LONG_STRING"


def test_search_hash_bytes_and_custom_salt():
    """Test SearchHash with bytes input and custom salt."""
    data = b"bytes_input_data"
    salt = b"custom_bytes_salt"

    hash_res = SearchHash(data, salt=salt)
    assert isinstance(hash_res, str)
    assert len(hash_res) == 64
    assert hash_res == SearchHash(data, salt=salt)


def test_rotate_dek_with_context():
    """Test rotate_dek re-encrypting ciphertext that has context AAD attached."""
    plaintext = "Data with Context AAD"
    old_key = os.urandom(32)
    new_key = os.urandom(32)
    ctx = "tenant_secret_context"

    ct_old = encrypt(plaintext, key=old_key, context=ctx)
    ct_new = rotate_dek(ct_old, new_key=new_key, old_key=old_key, context=ctx)

    assert decrypt(ct_new, key=new_key, context=ctx) == plaintext

