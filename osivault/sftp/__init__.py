"""
osivault.sftp: Enterprise-grade encrypted SFTP file transport and storage vault module.
Provides secure SSH tunneling, host key fingerprint verification, at-rest ciphertext file encryption,
YubiKey hardware-gated file decryption, SFTP Superuser management, and automated tamper-evident audit logging.
"""

from osivault.sftp.client import (
    SecureSFTPClient,
    SFTPSecurityError,
)
from osivault.sftp.host_keys import (
    StrictHostKeyPolicy,
    HostKeyVerificationError,
    get_host_key_fingerprint,
)
from osivault.sftp.crypto import (
    encrypt_file_payload,
    decrypt_file_payload,
    generate_sftp_key,
    compute_sha256,
    SFTPCryptoError,
)
from osivault.sftp.viewer import (
    verify_yubikey_and_decrypt_file,
    launch_secure_notepad_viewer,
    launch_secure_multi_notepad_viewer,
)
from osivault.sftp.utils import (
    get_sftp_vault_directory,
)

__all__ = [
    "SecureSFTPClient",
    "SFTPSecurityError",
    "StrictHostKeyPolicy",
    "HostKeyVerificationError",
    "get_host_key_fingerprint",
    "encrypt_file_payload",
    "decrypt_file_payload",
    "generate_sftp_key",
    "compute_sha256",
    "SFTPCryptoError",
    "verify_yubikey_and_decrypt_file",
    "launch_secure_notepad_viewer",
    "launch_secure_multi_notepad_viewer",
    "get_sftp_vault_directory",
]
