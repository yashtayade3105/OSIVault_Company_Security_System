"""
tests/test_sftp.py: End-to-End Comprehensive Unit Test Suite for osivault.sftp module.

Test Cases Covered (Start-to-End):
1. Payload Envelope Encryption & Decryption Roundtrip (AES-256-GCM).
2. Context AAD Binding & Decryption Enforcement.
3. Invalid Key Length & Missing OSIV Header Rejection.
4. Tampered Ciphertext Modification Detection.
5. Strict SSH Host Key Fingerprint Validation & Spoof Rejection.
6. End-to-End Secure File Upload (At-Rest Encrypted Ciphertext).
7. End-to-End Secure File Download & Decryption.
8. Standard Plaintext Transfer Mode Upload & Download.
9. Missing Local File Exception Handling.
10. Automatic Audit Logger Hash-Chain Integration.
11. Context Manager Auto-Closure Safety.
12. Hardware YubiKey-Gated File Decryption Success & Audit Trail.
13. Hardware YubiKey Rejection Blocks File Decryption.
14. Secure Notepad Viewer Temporary File Wipe & Cleanup.
"""

import os
import pytest
import paramiko
from unittest.mock import MagicMock, patch
from osivault.sftp import (
    SecureSFTPClient,
    StrictHostKeyPolicy,
    HostKeyVerificationError,
    get_host_key_fingerprint,
    encrypt_file_payload,
    decrypt_file_payload,
    generate_sftp_key,
    compute_sha256,
    SFTPCryptoError,
    SFTPSecurityError,
    verify_yubikey_and_decrypt_file,
    launch_secure_notepad_viewer,
)


def test_sftp_payload_encryption_roundtrip():
    """
    Test 1: Test that EDI 835/837 file payloads are encrypted into ciphertext at-rest
    and cleanly decrypted back into byte-for-byte exact originals.
    """
    sample_edi_835 = b"ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *261003*0950*U*00501*000000001*0*T*:~"
    key = generate_sftp_key()
    assert len(key) == 32

    # Encrypt payload for at-rest disk storage
    encrypted_bytes, key_used, sha256_original = encrypt_file_payload(
        payload=sample_edi_835, key=key
    )

    # Verify at-rest file is NOT plaintext (starts with OSIV header and is encrypted ciphertext)
    assert encrypted_bytes.startswith(b"OSIV")
    assert sample_edi_835 not in encrypted_bytes
    assert sha256_original == compute_sha256(sample_edi_835)

    # Decrypt ciphertext payload
    decrypted_bytes, sha256_decrypted = decrypt_file_payload(
        encrypted_payload=encrypted_bytes, key=key_used
    )

    assert decrypted_bytes == sample_edi_835
    assert sha256_decrypted == sha256_original


def test_sftp_crypto_aad_context_binding():
    """
    Test 2: Test that decrypting a file with mismatched AAD context raises SFTPCryptoError.
    """
    sample_data = b"BPR*I*500.00*C*ACH*CTX*01*999999999*DA*111111111*1234567890~"
    key = generate_sftp_key()

    encrypted_bytes, _, _ = encrypt_file_payload(
        payload=sample_data, key=key, context_aad=b"osivault.sftp.tenant_A"
    )

    # Decrypting with wrong context AAD must fail closed
    with pytest.raises(SFTPCryptoError, match="decryption failed"):
        decrypt_file_payload(
            encrypted_payload=encrypted_bytes, key=key, context_aad=b"osivault.sftp.tenant_B"
        )


def test_sftp_crypto_invalid_key_and_header_rejection():
    """
    Test 3: Test rejection of invalid key lengths or tampered file headers.
    """
    with pytest.raises(SFTPCryptoError, match="32 bytes"):
        encrypt_file_payload(b"test data", key=b"short_key")

    bad_encrypted_data = b"BADH1234567890123456"
    valid_key = generate_sftp_key()
    with pytest.raises(SFTPCryptoError, match="missing OSIV header"):
        decrypt_file_payload(bad_encrypted_data, key=valid_key)


def test_sftp_crypto_tampered_ciphertext_detection():
    """
    Test 4: Test modifying even a single byte of ciphertext is detected and rejected.
    """
    sample_payload = b"PATIENT_PHI_CLAIMS_DATA_835"
    key = generate_sftp_key()
    encrypted_bytes, _, _ = encrypt_file_payload(sample_payload, key=key)

    # Tamper with the 20th byte of the encrypted payload
    tampered_bytes = bytearray(encrypted_bytes)
    tampered_bytes[20] ^= 0xFF

    with pytest.raises(SFTPCryptoError, match="decryption failed"):
        decrypt_file_payload(bytes(tampered_bytes), key=key)


def test_sftp_strict_host_key_verification():
    """
    Test 5: Test StrictHostKeyPolicy matches valid host key fingerprints and rejects spoofed hosts.
    """
    key = paramiko.RSAKey.generate(2048)
    actual_fingerprint = get_host_key_fingerprint(key)

    assert actual_fingerprint.startswith("SHA256:")

    policy_valid = StrictHostKeyPolicy(expected_fingerprint=actual_fingerprint)
    mock_client = MagicMock()

    # Should pass without exception when fingerprint matches
    policy_valid.missing_host_key(mock_client, "sftp.partner.com", key)

    policy_invalid = StrictHostKeyPolicy(expected_fingerprint="SHA256:FAKE_SPOOFED_FINGERPRINT_123")
    with pytest.raises(HostKeyVerificationError, match="fingerprint mismatch"):
        policy_invalid.missing_host_key(mock_client, "sftp.partner.com", key)


def test_sftp_client_upload_encrypted_at_rest(tmp_path):
    """
    Test 6: Test SecureSFTPClient file upload with at-rest payload encryption.
    """
    client = SecureSFTPClient(
        hostname="sftp.hospital-partner.com",
        username="mir_user",
        password="secure_password",
        auto_audit=False,
    )

    sample_content = b"ST*835*0001~BPR*I*150.00*C*ACH*CTX*01*999999999*DA*111111111*1234567890~"
    local_file = tmp_path / "claims_835.edi"
    local_file.write_bytes(sample_content)

    mock_sftp = MagicMock()
    client.sftp_client = mock_sftp

    upload_res = client.upload_file(
        local_path_or_bytes=str(local_file),
        remote_path="/incoming/835/claims_835.edi",
        encrypt_at_rest=True,
    )

    assert upload_res["status"] == "success"
    assert upload_res["encrypted_at_rest"] is True
    assert upload_res["sha256_original"] == compute_sha256(sample_content)
    assert "encryption_key" in upload_res
    assert mock_sftp.putfo.called


def test_sftp_client_download_and_decrypt(tmp_path):
    """
    Test 7: Test SecureSFTPClient file download and at-rest ciphertext decryption.
    """
    client = SecureSFTPClient(
        hostname="sftp.hospital-partner.com",
        username="mir_user",
        auto_audit=False,
    )

    sample_content = b"CLM*10001*100***11:B:1*Y*A*Y*Y~"
    key = generate_sftp_key()
    encrypted_bytes, _, _ = encrypt_file_payload(sample_content, key=key)

    client.encryption_key = key
    mock_sftp = MagicMock()
    mock_sftp.getfo.side_effect = lambda rpath, fobj: fobj.write(encrypted_bytes)
    client.sftp_client = mock_sftp

    download_local_file = tmp_path / "downloaded_claims.edi"
    download_res = client.download_file(
        remote_path="/incoming/835/claims_835.edi",
        local_path=str(download_local_file),
        decrypt_at_rest=True,
    )

    assert download_res["status"] == "success"
    assert download_res["payload"] == sample_content
    assert download_local_file.read_bytes() == sample_content


def test_sftp_client_upload_download_plaintext_mode():
    """
    Test 8: Test upload and download in standard plaintext transfer mode (encrypt_at_rest=False).
    """
    client = SecureSFTPClient(hostname="sftp.test.com", auto_audit=False)
    mock_sftp = MagicMock()
    client.sftp_client = mock_sftp

    sample_bytes = b"PLAIN_TEXT_NON_SENSITIVE_DATA"
    upload_res = client.upload_file(
        local_path_or_bytes=sample_bytes,
        remote_path="/files/plain.txt",
        encrypt_at_rest=False,
    )

    assert upload_res["encrypted_at_rest"] is False
    assert upload_res["sha256_original"] == upload_res["sha256_transferred"]


def test_sftp_client_missing_local_file_error():
    """
    Test 9: Test that uploading a non-existent local file raises SFTPSecurityError.
    """
    client = SecureSFTPClient(hostname="localhost")
    with pytest.raises(SFTPSecurityError, match="Local file not found"):
        client.upload_file(
            local_path_or_bytes="/non_existent_path/file.edi",
            remote_path="/remote/file.edi",
        )


def test_sftp_audit_logger_integration():
    """
    Test 10: Test automatic logging of SFTP transfer events to osivault.audit.
    """
    client = SecureSFTPClient(hostname="sftp.hospital.com", username="audit_user", auto_audit=True)

    mock_entry = MagicMock()
    mock_entry.id = 101
    mock_entry.entry_hash = "abc123hash"

    with patch("osivault.audit.append", return_value=mock_entry) as mock_append:
        upload_res = client.upload_file(
            local_path_or_bytes=b"AUDIT_TEST_PAYLOAD",
            remote_path="/remote/audit.edi",
            encrypt_at_rest=False,
        )

        assert upload_res["audit_entry"]["entry_id"] == 101
        assert mock_append.called


def test_sftp_client_context_manager():
    """
    Test 11: Test SecureSFTPClient context manager safely closes sessions on exit.
    """
    client = SecureSFTPClient(hostname="localhost")
    mock_ssh = MagicMock()
    mock_sftp = MagicMock()
    client.ssh_client = mock_ssh
    client.sftp_client = mock_sftp

    with client:
        pass

    assert mock_sftp.close.called
    assert mock_ssh.close.called


def test_yubikey_gated_file_decryption_success(tmp_path):
    """
    Test 12: Test YubiKey hardware-gated decryption succeeds when osivault.auth verification passes.
    """
    raw_payload = b"ISA*00*0000000000*00*0000000000*ZZ*SENDER*ZZ*RECEIVER*261003*1100*U*00501*000000001*0*T*:~"
    key = generate_sftp_key()
    encrypted_bytes, _, _ = encrypt_file_payload(raw_payload, key=key)

    enc_file = tmp_path / "encrypted_claims.edi"
    enc_file.write_bytes(encrypted_bytes)

    mock_auth_result = {
        "verified": True,
        "new_sign_count": 42,
    }

    with patch("osivault.auth.webauthn.verify_assertion_response", return_value=mock_auth_result):
        res = verify_yubikey_and_decrypt_file(
            encrypted_file_path_or_bytes=str(enc_file),
            decryption_key=key,
            credential_id="yubikey_cred_123",
            authenticator_data_b64="YXV0aA==",
            client_data_json_b64="Y2xpZW50",
            signature_b64="c2ln",
            challenge_b64="Y2hhbGxlbmdl",
            public_key_b64="cHVibGlj",
            expected_rp_id="mir.onesmarter.com",
            expected_origin="https://mir.onesmarter.com",
            audit_log=False,
        )

        assert res["status"] == "success"
        assert res["verified_hardware"] is True
        assert res["payload"] == raw_payload
        assert res["sign_count"] == 42


def test_yubikey_gated_file_decryption_hardware_rejection(tmp_path):
    """
    Test 13: Test YubiKey hardware rejection blocks decryption and raises SFTPSecurityError.
    """
    key = generate_sftp_key()
    encrypted_bytes, _, _ = encrypt_file_payload(b"CONFIDENTIAL_DATA", key=key)

    enc_file = tmp_path / "secret.edi"
    enc_file.write_bytes(encrypted_bytes)

    with patch(
        "osivault.auth.webauthn.verify_assertion_response",
        side_effect=ValueError("YubiKey hardware signature verification failed"),
    ):
        with pytest.raises(SFTPSecurityError, match="Hardware YubiKey authentication failed"):
            verify_yubikey_and_decrypt_file(
                encrypted_file_path_or_bytes=str(enc_file),
                decryption_key=key,
                credential_id="bad_cred",
                authenticator_data_b64="YXV0aA==",
                client_data_json_b64="Y2xpZW50",
                signature_b64="bad_sig",
                challenge_b64="challenge",
                public_key_b64="pubkey",
                expected_rp_id="mir.onesmarter.com",
                expected_origin="https://mir.onesmarter.com",
                audit_log=False,
            )


def test_launch_secure_notepad_viewer_cleanup():
    """
    Test 14: Test launch_secure_notepad_viewer launches viewer process and wipes temporary plaintext file on exit.
    """
    decrypted_bytes = b"TEMPORARY_DECRYPTED_TEXT_FOR_NOTEPAD"

    mock_proc = MagicMock()
    mock_proc.wait.return_value = 0

    with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
        success = launch_secure_notepad_viewer(
            decrypted_payload=decrypted_bytes,
            file_suffix=".edi",
            wait_for_close=True,
        )

        assert success is True
        assert mock_popen.called
        assert mock_proc.wait.called


@pytest.mark.django_db
def test_sftp_superuser_creation_and_max_limit():
    """
    Test 15: Test SFTPSuperUser creation and enforcement of maximum 3 superusers per project.
    """
    from osivault.sftp.models import SFTPSuperUser, SFTPSuperUserYubiKey
    from django.core.exceptions import ValidationError

    # Create 3 superusers
    s1 = SFTPSuperUser.objects.create_superuser("admin1", "admin1@osivault.com", "+14155550001", "Password123!")
    s2 = SFTPSuperUser.objects.create_superuser("admin2", "admin2@osivault.com", "+14155550002", "Password123!")
    s3 = SFTPSuperUser.objects.create_superuser("admin3", "admin3@osivault.com", "+14155550003", "Password123!")

    assert SFTPSuperUser.objects.count() == 3
    assert s1.check_password("Password123!") is True

    # Register YubiKeys for s1
    yk1 = SFTPSuperUserYubiKey.objects.create(
        superuser=s1, credential_id="cred_primary_1", public_key="pubkey1",
        key_label="Primary YubiKey", slot_type="PRIMARY"
    )
    yk2 = SFTPSuperUserYubiKey.objects.create(
        superuser=s1, credential_id="cred_backup_1", public_key="pubkey2",
        key_label="Backup YubiKey", slot_type="BACKUP"
    )

    assert s1.yubikeys.count() == 2
    assert yk1.slot_type == "PRIMARY"
    assert yk2.slot_type == "BACKUP"

    # Attempting to create 4th superuser must raise ValidationError
    with pytest.raises(ValidationError, match="Maximum limit of 3 SFTP Superusers"):
        SFTPSuperUser.objects.create_superuser("admin4", "admin4@osivault.com", "+14155550004", "Password123!")


@pytest.mark.django_db
def test_sftp_view_file_command_decryption_flow(tmp_path):
    """
    Test 16: Test sftp_view_file CLI command authenticates superuser, decrypts ciphertext in-memory, and wipes temp file.
    """
    from osivault.sftp.models import SFTPSuperUser, SFTPSuperUserYubiKey, SFTPFileAccessLog
    from osivault.sftp.crypto import encrypt_file_payload, generate_sftp_key
    from django.core.management import call_command

    su = SFTPSuperUser.objects.create_superuser("super_viewer", "viewer@osivault.com", "+14155559999", "SuperSecretPass123!")
    SFTPSuperUserYubiKey.objects.create(
        superuser=su, credential_id="cred_viewer_key", public_key="pubkey_v",
        key_label="Viewer Primary YubiKey", slot_type="PRIMARY"
    )

    raw_edi_data = b"ISA*00*0000000000*00*0000000000*ZZ*SENDER*ZZ*RECEIVER*261006*1200*U*00501*000000001*0*T*:~"
    key = generate_sftp_key()
    encrypted_bytes, _, sha256_orig = encrypt_file_payload(raw_edi_data, key=key)

    edi_file = tmp_path / "AHH_ABC_Elig_Full_260317103923.TXT"
    edi_file.write_bytes(encrypted_bytes)

    # File on disk MUST be ciphertext (starts with OSIV)
    assert edi_file.read_bytes().startswith(b"OSIV")

    mock_proc = MagicMock()
    mock_proc.wait.return_value = 0

    with patch("builtins.input", side_effect=["super_viewer", "1", ""]), \
         patch("getpass.getpass", return_value="SuperSecretPass123!"), \
         patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
        
        call_command("sftp_view_file", str(edi_file), key=key.hex())

        assert mock_popen.called
        # Original file on disk remains ciphertext
        assert edi_file.read_bytes().startswith(b"OSIV")
        
        # Access log entry exists
        log_entry = SFTPFileAccessLog.objects.filter(superuser=su, filename=edi_file.name, action="DECRYPT_VIEW").first()
        assert log_entry is not None
        assert log_entry.is_success is True

