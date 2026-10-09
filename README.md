# 🛡️ OSIVault: Enterprise Security System Core Suite

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://python.org)
[![Django Framework](https://img.shields.io/badge/django-4.2%20%7C%205.0%20%7C%206.0%2B-green.svg)](https://djangoproject.com)
[![Security Standard](https://img.shields.io/badge/security-HIPAA%20%7C%20PCI--DSS%20%7C%20FIDO2-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**OSIVault** is a SaaS-level, zero-trust enterprise security core system designed for Django & Python applications. It provides zero-trust field-level encryption at rest, hardware-gated YubiKey WebAuthn/FIDO2 multi-factor authentication, encrypted SFTP payload transport with multi-tab self-destructing viewers, and tamper-evident cryptographic hash-chain audit trail logging.

---

## 🚀 Quick Installation (3 Steps)

### Step 1: Install OSIVault
```bash
pip install osivault
```
*(Or include the `osivault` package directory directly in your project root)*

### Step 2: Register OSIVault in Django `settings.py`
Add `osivault` modules to your `INSTALLED_APPS` and middleware in `settings.py`:

```python
INSTALLED_APPS = [
    # ... Standard Django Apps ...
    
    # OSIVault Security System Core Modules
    "osivault.audit",
    "osivault.auth",
    "osivault.fields",
    "osivault.sftp",
]

MIDDLEWARE = [
    # ... Standard Middleware ...
    "osivault.audit.OSIVaultAuditMiddleware",  # Auto-captures tamper-evident audit logs
]

# Vault Directory for Encrypted Files (Optional, defaults to D:\Transfers\Server_Directory or OS env)
SERVER_VAULT_DIRECTORY = os.environ.get("OSIVAULT_SFTP_DIRECTORY", r"D:\Transfers\Server_Directory")
```

### Step 3: Run Database Migrations
```bash
python manage.py migrate
```

---

## 📦 OSIVault Core Modules & Developer Integration Guides

---

### 🔑 1. `osivault.auth` — Hardware YubiKey WebAuthn / FIDO2 MFA

Hardware-gated Multi-Factor Authentication supporting physical YubiKey 5 Series (NFC/USB-C) touch sensors with FIDO2 WebAuthn assertion verification and clone-detection sign counters.

#### **Developer Integration Steps:**

1. **Import `verify_assertion_response`**:
```python
from osivault.auth.webauthn import verify_assertion_response

# Verify YubiKey physical contact & signature assertion
auth_result = verify_assertion_response(
    credential_id=credential_id,
    authenticator_data_b64=auth_data_b64,
    client_data_json_b64=client_data_b64,
    signature_b64=signature_b64,
    challenge_b64=challenge_b64,
    public_key_b64=public_key_b64,
    expected_rp_id="yourdomain.com",
    expected_origin="https://yourdomain.com",
    current_sign_count=user_yubikey.sign_count,
)

if auth_result["verified"]:
    print("YubiKey Touch Verified! Sign Count:", auth_result["new_sign_count"])
```

2. **Register Superusers & Dual YubiKeys via CLI**:
```bash
python manage.py create_sftp_superuser
```

---

### 🛡️ 2. `osivault.sftp` — Encrypted SFTP Transport & Terminal Viewer

Provides AES-256-GCM envelope file payload encryption with `OSIV` magic header, universal directory resolution across any OS, and terminal-based hardware-gated multi-tab self-destructing Notepad viewer.

#### **Developer Integration Steps:**

1. **Encrypt File Payload Before Writing to Disk**:
```python
from osivault.sftp.crypto import encrypt_file_payload

# Encrypt raw bytes with AES-256-GCM & OSIV magic header
encrypted_payload, key_used, sha256_hash = encrypt_file_payload(raw_bytes)

with open("/path/to/server_directory/file.edi", "wb") as f:
    f.write(encrypted_payload)
```

2. **Decrypt File Payload In-Memory**:
```python
from osivault.sftp.crypto import decrypt_file_payload

# Decrypt in RAM (raises SFTPCryptoError if file is corrupted/tampered)
decrypted_bytes, sha256_hash = decrypt_file_payload(encrypted_bytes, key=key_used)
```

3. **Secure Hardware Terminal Multi-Tab Viewer CLI**:
```bash
# Scan directory & view files in self-destructing Notepad tabs after YubiKey verification
python manage.py sftp_view_file /var/sftp/server_directory
```

---

### 🔐 3. `osivault.fields` — Encrypted Model Fields with Blind Index Search

Zero-trust field-level encryption for Django models. Sensitive fields (SSN, Phone Numbers, Addresses, Credit Cards) are encrypted with AES-256-GCM at rest, while maintaining ultra-fast database searchability using HMAC-SHA-256 Blind Index Hashing (`SearchHash`).

#### **Developer Integration Steps:**

1. **Use Encrypted Fields in Model Definition**:
```python
from django.db import models
from osivault.fields import SearchHash

class PatientRecord(models.Model):
    patient_name = models.CharField(max_length=255)
    # Encrypted field stored as ciphertext
    ssn_encrypted = models.CharField(max_length=512)
    # HMAC Blind Index for zero-trust search queries
    ssn_blind_hash = models.CharField(max_length=64, db_index=True)

    def set_ssn(self, raw_ssn: str):
        # Store HMAC Blind Index for fast DB lookup
        self.ssn_blind_hash = SearchHash(raw_ssn)
        # Store encrypted payload
```

---

### 📜 4. `osivault.audit` — Tamper-Evident Hash-Chain Audit Logging

Cryptographic, tamper-evident audit logging using SHA-256 Merkle hash-chaining. Every event is linked to the previous log's SHA-256 hash. If any past record in the database is modified or deleted by a rogue database admin, the hash chain breaks instantly!

#### **Developer Integration Steps:**

1. **Append Audit Event to Hash-Chain**:
```python
from osivault.audit import append

# Cryptographically link event to audit chain
entry = append(
    event_type="SECURITY_FILE_DECRYPTED",
    actor="admin_user",
    details={
        "filename": "AHH_ABC_Elig_Full_250901123941.TXT",
        "sha256_hash": "3b22818b88078ba45cd3008e14f...",
        "action": "YUBIKEY_HARDWARE_VIEW"
    }
)

print(f"Logged Audit Entry #{entry.id} Hash: {entry.entry_hash}")
```

2. **Verify Audit Chain Integrity**:
```python
from osivault.audit import verify_chain_integrity

# Scans entire database table to verify tamper-evident hash links
is_valid, broken_entry_id = verify_chain_integrity()
if is_valid:
    print("Audit Log Hash-Chain 100% Intact & Verified!")
```

---

## 🛠️ Running Unit Tests

Run the complete pytest test suite:
```bash
python -m pytest -v
```

---

## 📄 License & Attribution

MIT License. Copyright (c) 2026 Yash Tayade & OSIVault Security Engineering Team.
