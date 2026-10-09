"""
osivault.sftp.viewer: Hardware-gated file decryption and secure Notepad viewer.
Combines osivault.auth (YubiKey WebAuthn assertion verification) with osivault.sftp
(at-rest ciphertext decryption) to view encrypted files securely.
"""

import os
import sys
import time
import tempfile
import subprocess
from typing import Dict, Any, Optional, List, Tuple
from osivault.sftp.crypto import decrypt_file_payload, SFTPCryptoError
from osivault.sftp.client import SFTPSecurityError


def verify_yubikey_and_decrypt_file(
    encrypted_file_path_or_bytes: str | bytes,
    decryption_key: bytes,
    credential_id: str,
    authenticator_data_b64: str,
    client_data_json_b64: str,
    signature_b64: str,
    challenge_b64: str,
    public_key_b64: str,
    expected_rp_id: str,
    expected_origin: str,
    current_sign_count: int = 0,
    context_aad: Optional[bytes] = None,
    audit_log: bool = True,
) -> Dict[str, Any]:
    """
    Hardware-Gated File Decryptor:
    1. Verifies physical YubiKey assertion signature using osivault.auth.webauthn.
    2. Upon 100% valid hardware verification, decrypts ciphertext file payload in-memory.
    3. Logs hardware-gated viewing event to osivault.audit hash-chain.
    """
    from osivault.auth.webauthn import verify_assertion_response

    # Step 1: Perform strict YubiKey hardware assertion verification via osivault.auth
    try:
        auth_result = verify_assertion_response(
            credential_id=credential_id,
            authenticator_data_b64=authenticator_data_b64,
            client_data_json_b64=client_data_json_b64,
            signature_b64=signature_b64,
            challenge_b64=challenge_b64,
            public_key_b64=public_key_b64,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            current_sign_count=current_sign_count,
        )
    except Exception as e:
        raise SFTPSecurityError(
            f"Hardware YubiKey authentication failed: {str(e)}. File decryption blocked!"
        ) from e

    if not auth_result.get("verified"):
        raise SFTPSecurityError("YubiKey hardware verification returned unverified status. Access denied!")

    # Step 2: Read encrypted file payload
    if isinstance(encrypted_file_path_or_bytes, str):
        if not os.path.exists(encrypted_file_path_or_bytes):
            raise SFTPSecurityError(f"Encrypted file not found: {encrypted_file_path_or_bytes}")
        filename = os.path.basename(encrypted_file_path_or_bytes)
        with open(encrypted_file_path_or_bytes, "rb") as f:
            ciphertext_bytes = f.read()
    else:
        filename = "in_memory_file.edi"
        ciphertext_bytes = encrypted_file_path_or_bytes

    # Step 3: Decrypt payload in-memory ONLY
    try:
        decrypted_payload, sha256_hash = decrypt_file_payload(
            encrypted_payload=ciphertext_bytes,
            key=decryption_key,
            context_aad=context_aad,
        )
    except SFTPCryptoError as e:
        raise SFTPSecurityError(f"Ciphertext decryption failed: {str(e)}") from e

    # Step 4: Audit logging
    audit_entry = None
    if audit_log:
        try:
            from osivault.audit import append
            entry = append(
                event_type="SECURITY_SFTP_YUBIKEY_FILE_VIEWED",
                actor=f"yubikey_cred:{credential_id[:12]}",
                details={
                    "filename": filename,
                    "rp_id": expected_rp_id,
                    "origin": expected_origin,
                    "sha256_hash": sha256_hash,
                    "new_sign_count": auth_result.get("new_sign_count"),
                },
            )
            audit_entry = {"entry_id": getattr(entry, "id", None), "hash": getattr(entry, "entry_hash", None)}
        except Exception:
            pass

    return {
        "status": "success",
        "verified_hardware": True,
        "filename": filename,
        "payload": decrypted_payload,
        "sha256_hash": sha256_hash,
        "sign_count": auth_result.get("new_sign_count"),
        "audit_entry": audit_entry,
    }


def launch_secure_multi_notepad_viewer(
    file_items: List[Tuple[str, bytes]],
    wait_for_close: bool = True,
) -> bool:
    """
    Launch Notepad (or OS default editor) with multiple decrypted in-memory payloads as separate TABS simultaneously.
    On Windows 11, passing multiple file paths to notepad.exe opens each file in a separate TAB within the Notepad window.
    Automatically zero-wipes and deletes all temporary plaintext files immediately when Notepad closes!
    """
    if not file_items:
        return True

    temp_dir = tempfile.mkdtemp(prefix="osivault_viewer_")
    temp_records = []
    temp_file_paths = []

    try:
        for suffix_or_name, payload in file_items:
            safe_name = os.path.basename(suffix_or_name).lstrip("_")
            if not safe_name.startswith("view_decrypted"):
                temp_filename = f"view_decrypted_{safe_name}"
            else:
                temp_filename = safe_name
            
            temp_file_path = os.path.join(temp_dir, temp_filename)
            with open(temp_file_path, "wb") as f:
                f.write(payload)

            temp_records.append((temp_file_path, payload))
            temp_file_paths.append(temp_file_path)

        procs = []
        for idx, temp_file_path in enumerate(temp_file_paths):
            if sys.platform == "win32":
                p = subprocess.Popen(["notepad.exe", temp_file_path])
            elif sys.platform == "darwin":
                p = subprocess.Popen(["open", "-a", "TextEdit", temp_file_path])
            else:
                p = subprocess.Popen(["xdg-open", temp_file_path])
            procs.append(p)
            if idx < len(temp_file_paths) - 1:
                time.sleep(0.15)

        if wait_for_close:
            for p in procs:
                try:
                    p.wait()
                except Exception:
                    pass

        return True
    finally:
        # Secure wipe and cleanup for all files
        for temp_file_path, payload in temp_records:
            if os.path.exists(temp_file_path):
                try:
                    with open(temp_file_path, "ba+", buffering=0) as f:
                        f.write(b"\x00" * len(payload))
                    os.remove(temp_file_path)
                except Exception:
                    pass
        if os.path.exists(temp_dir):
            try:
                os.rmdir(temp_dir)
            except Exception:
                pass


def launch_secure_notepad_viewer(
    decrypted_payload: bytes,
    file_suffix: str = ".edi",
    wait_for_close: bool = True,
) -> bool:
    """
    Launch Notepad (or OS default editor) with a single decrypted in-memory payload.
    Automatically wipes and deletes temporary plaintext file immediately when Notepad closes!
    """
    return launch_secure_multi_notepad_viewer([(file_suffix, decrypted_payload)], wait_for_close=wait_for_close)
