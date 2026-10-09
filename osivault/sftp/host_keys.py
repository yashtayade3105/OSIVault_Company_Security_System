"""
osivault.sftp.host_keys: Strict SSH host key fingerprint verification.
Enforces zero-trust host key validation to prevent Man-in-the-Middle (MitM) attacks.
"""

import base64
import hashlib
import paramiko


class HostKeyVerificationError(Exception):
    """Raised when SSH host key fingerprint verification fails."""
    pass


def get_host_key_fingerprint(key: paramiko.PKey) -> str:
    """Calculate SHA-256 fingerprint string for a Paramiko SSH public key."""
    key_bytes = key.asbytes()
    sha256_hash = hashlib.sha256(key_bytes).digest()
    b64_fingerprint = base64.b64encode(sha256_hash).decode("utf-8").rstrip("=")
    return f"SHA256:{b64_fingerprint}"


class StrictHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Paramiko MissingHostKeyPolicy enforcing strict expected SHA-256 fingerprint verification.
    Rejects unknown or mismatched SSH host keys automatically.
    """

    def __init__(self, expected_fingerprint: str):
        self.expected_fingerprint = expected_fingerprint.strip() if expected_fingerprint else None

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey):
        actual_fingerprint = get_host_key_fingerprint(key)

        if not self.expected_fingerprint:
            raise HostKeyVerificationError(
                f"Strict host key verification failed for {hostname}: No expected fingerprint provided. "
                f"Server presented fingerprint: {actual_fingerprint}"
            )

        if actual_fingerprint != self.expected_fingerprint:
            raise HostKeyVerificationError(
                f"Host key fingerprint mismatch for {hostname}! "
                f"Expected: {self.expected_fingerprint}, Actual: {actual_fingerprint}. "
                f"Potential Man-in-the-Middle (MitM) attack detected!"
            )
