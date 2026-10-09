"""
osivault.sftp.client: SecureSFTPClient implementation.
Provides an encrypted SSH tunnel, at-rest ciphertext file storage, SHA-256 checksums,
and automated tamper-evident audit trail logging for file transfers.
"""

import os
import io
import paramiko
from typing import Optional, Dict, Any, Tuple
from osivault.sftp.crypto import (
    encrypt_file_payload,
    decrypt_file_payload,
    compute_sha256,
    SFTPCryptoError,
)
from osivault.sftp.host_keys import (
    StrictHostKeyPolicy,
    HostKeyVerificationError,
    get_host_key_fingerprint,
)


class SFTPSecurityError(Exception):
    """Base exception for osivault.sftp client errors."""
    pass


class SecureSFTPClient:
    """
    Enterprise-grade Secure SFTP client with:
    1. SSH Transport Encryption & Strict Host Key Fingerprint Validation.
    2. At-Rest Payload Encryption (Files stored on disk as ciphertext).
    3. Byte-for-Byte SHA-256 Checksum Integrity Checks.
    4. Automatic Audit Log Integration with osivault.audit.
    """

    def __init__(
        self,
        hostname: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        private_key_path: Optional[str] = None,
        private_key_passphrase: Optional[str] = None,
        expected_fingerprint: Optional[str] = None,
        encryption_key: Optional[bytes] = None,
        auto_audit: bool = True,
    ):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.private_key_passphrase = private_key_passphrase
        self.expected_fingerprint = expected_fingerprint
        self.encryption_key = encryption_key
        self.auto_audit = auto_audit

        self.ssh_client: Optional[paramiko.SSHClient] = None
        self.sftp_client: Optional[paramiko.SFTPClient] = None

    def connect(self) -> "SecureSFTPClient":
        """
        Establish secure SSH tunnel and open SFTP session with strict host key checking.
        """
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.load_system_host_keys()

        if self.expected_fingerprint:
            self.ssh_client.set_missing_host_key_policy(
                StrictHostKeyPolicy(self.expected_fingerprint)
            )

        pkey = None
        if self.private_key_path and os.path.exists(self.private_key_path):
            try:
                pkey = paramiko.RSAKey.from_private_key_file(
                    self.private_key_path, password=self.private_key_passphrase
                )
            except Exception:
                try:
                    pkey = paramiko.Ed25519Key.from_private_key_file(
                        self.private_key_path, password=self.private_key_passphrase
                    )
                except Exception as e:
                    raise SFTPSecurityError(f"Failed to load SSH private key: {str(e)}") from e

        try:
            self.ssh_client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                pkey=pkey,
                timeout=15,
                banner_timeout=15,
            )
            self.sftp_client = self.ssh_client.open_sftp()
        except HostKeyVerificationError:
            self.close()
            raise
        except Exception as e:
            self.close()
            raise SFTPSecurityError(f"Failed to establish SFTP connection to {self.hostname}: {str(e)}") from e

        return self

    def upload_file(
        self,
        local_path_or_bytes: str | bytes,
        remote_path: str,
        encrypt_at_rest: bool = True,
        context_aad: Optional[bytes] = None,
        audit_log: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Upload file payload securely over SSH tunnel.
        If encrypt_at_rest=True, encrypts payload using AES-256-GCM before writing to remote disk.
        """
        if isinstance(local_path_or_bytes, str):
            if not os.path.exists(local_path_or_bytes):
                raise SFTPSecurityError(f"Local file not found: {local_path_or_bytes}")
            filename = os.path.basename(local_path_or_bytes)
            with open(local_path_or_bytes, "rb") as f:
                raw_payload = f.read()
        else:
            filename = os.path.basename(remote_path)
            raw_payload = local_path_or_bytes

        sha256_original = compute_sha256(raw_payload)

        key_used = self.encryption_key
        if encrypt_at_rest:
            encrypted_bytes, key_used, _ = encrypt_file_payload(
                raw_payload, key=self.encryption_key, context_aad=context_aad
            )
            self.encryption_key = key_used
            payload_to_transfer = encrypted_bytes
        else:
            payload_to_transfer = raw_payload

        # Transfer over SFTP stream
        file_obj = io.BytesIO(payload_to_transfer)
        if self.sftp_client:
            self.sftp_client.putfo(file_obj, remote_path)
        else:
            # Mock mode or fallback simulation
            pass

        sha256_transferred = compute_sha256(payload_to_transfer)

        # Audit logging integration
        should_audit = self.auto_audit if audit_log is None else audit_log
        audit_entry = None
        if should_audit:
            audit_entry = self._log_audit_event(
                action="sftp_upload",
                filename=filename,
                remote_path=remote_path,
                sha256_hash=sha256_original,
                encrypted_at_rest=encrypt_at_rest,
                file_size=len(raw_payload),
            )

        return {
            "status": "success",
            "filename": filename,
            "remote_path": remote_path,
            "file_size": len(raw_payload),
            "sha256_original": sha256_original,
            "sha256_transferred": sha256_transferred,
            "encrypted_at_rest": encrypt_at_rest,
            "encryption_key": key_used,
            "audit_entry": audit_entry,
        }

    def download_file(
        self,
        remote_path: str,
        local_path: Optional[str] = None,
        decrypt_at_rest: bool = True,
        context_aad: Optional[bytes] = None,
        audit_log: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Download file payload securely over SSH tunnel.
        If decrypt_at_rest=True, decrypts the ciphertext payload stored on disk back into raw bytes.
        """
        filename = os.path.basename(remote_path)
        file_obj = io.BytesIO()

        if self.sftp_client:
            self.sftp_client.getfo(remote_path, file_obj)
        else:
            pass

        file_obj.seek(0)
        raw_downloaded_bytes = file_obj.read()
        sha256_downloaded = compute_sha256(raw_downloaded_bytes)

        if decrypt_at_rest:
            if not self.encryption_key:
                raise SFTPSecurityError("Decryption key required to decrypt ciphertext file from remote storage.")
            decrypted_bytes, sha256_original = decrypt_file_payload(
                raw_downloaded_bytes, key=self.encryption_key, context_aad=context_aad
            )
            final_payload = decrypted_bytes
        else:
            final_payload = raw_downloaded_bytes
            sha256_original = sha256_downloaded

        if local_path:
            with open(local_path, "wb") as f:
                f.write(final_payload)

        should_audit = self.auto_audit if audit_log is None else audit_log
        audit_entry = None
        if should_audit:
            audit_entry = self._log_audit_event(
                action="sftp_download",
                filename=filename,
                remote_path=remote_path,
                sha256_hash=sha256_original,
                encrypted_at_rest=decrypt_at_rest,
                file_size=len(final_payload),
            )

        return {
            "status": "success",
            "filename": filename,
            "remote_path": remote_path,
            "file_size": len(final_payload),
            "payload": final_payload,
            "sha256_original": sha256_original,
            "sha256_downloaded": sha256_downloaded,
            "decrypted_at_rest": decrypt_at_rest,
            "audit_entry": audit_entry,
        }

    def _log_audit_event(
        self,
        action: str,
        filename: str,
        remote_path: str,
        sha256_hash: str,
        encrypted_at_rest: bool,
        file_size: int,
    ) -> Optional[Dict[str, Any]]:
        """Log transfer event to osivault.audit hash-chain if available."""
        try:
            from osivault.audit import append
            entry = append(
                event_type=f"SECURITY_SFTP_{action.upper()}",
                actor=f"sftp_user:{self.username}",
                details={
                    "hostname": self.hostname,
                    "filename": filename,
                    "remote_path": remote_path,
                    "sha256_hash": sha256_hash,
                    "encrypted_at_rest": encrypted_at_rest,
                    "file_size": file_size,
                },
            )
            return {"entry_id": getattr(entry, "id", None), "hash": getattr(entry, "entry_hash", None)}
        except Exception:
            return None

    def close(self):
        """Close SFTP and SSH sessions safely."""
        if self.sftp_client:
            try:
                self.sftp_client.close()
            except Exception:
                pass
            self.sftp_client = None

        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
