"""
osivault.sftp.crypto: Envelope encryption and checksum integrity for file payloads.
Ensures files stored on remote/client disk are encrypted (ciphertext) rather than plaintext.
"""

import os
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SFTPCryptoError(Exception):
    """Base exception for osivault.sftp crypto operations."""
    pass


def generate_sftp_key() -> bytes:
    """Generate a fresh AES-256 key for file payload encryption."""
    return AESGCM.generate_key(bit_length=256)


def compute_sha256(data: bytes) -> str:
    """Compute hex SHA-256 checksum of file data."""
    return hashlib.sha256(data).hexdigest()


def encrypt_file_payload(
    payload: bytes,
    key: Optional[bytes] = None,
    context_aad: Optional[bytes] = None,
) -> Tuple[bytes, bytes, str]:
    """
    Encrypt file payload using AES-256-GCM.
    
    Returns:
        Tuple of (encrypted_bytes, key_used, sha256_original_checksum)
    """
    if not isinstance(payload, bytes):
        payload = str(payload).encode("utf-8")

    sha256_original = compute_sha256(payload)
    encryption_key = key or generate_sftp_key()

    if len(encryption_key) != 32:
        raise SFTPCryptoError("AES-256 key must be exactly 32 bytes.")

    aesgcm = AESGCM(encryption_key)
    nonce = os.urandom(12)
    aad = context_aad or b"osivault.sftp.v1"

    ciphertext = aesgcm.encrypt(nonce, payload, aad)
    # Header format: magic (4 bytes) + nonce (12 bytes) + ciphertext
    magic_header = b"OSIV"
    encrypted_file_bytes = magic_header + nonce + ciphertext

    return encrypted_file_bytes, encryption_key, sha256_original


def decrypt_file_payload(
    encrypted_payload: bytes,
    key: bytes,
    context_aad: Optional[bytes] = None,
) -> Tuple[bytes, str]:
    """
    Decrypt file payload using AES-256-GCM.
    
    Returns:
        Tuple of (decrypted_original_bytes, sha256_decrypted_checksum)
    """
    if len(key) != 32:
        raise SFTPCryptoError("AES-256 key must be exactly 32 bytes.")

    magic_header = encrypted_payload[:4]
    if magic_header != b"OSIV":
        raise SFTPCryptoError("Invalid OSIVault encrypted file format (missing OSIV header).")

    nonce = encrypted_payload[4:16]
    ciphertext = encrypted_payload[16:]
    aad = context_aad or b"osivault.sftp.v1"

    try:
        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception as e:
        raise SFTPCryptoError(f"File decryption failed: {str(e)}") from e

    sha256_checksum = compute_sha256(decrypted_bytes)
    return decrypted_bytes, sha256_checksum
