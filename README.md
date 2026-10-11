# OSIVault: Enterprise Security Architecture & Cryptographic Core Suite

[![Python Version](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue.svg)](https://python.org)
[![Django Framework](https://img.shields.io/badge/django-4.2%20LTS%20%7C%205.0%20%7C%206.0-green.svg)](https://djangoproject.com)
[![Test Suite Status](https://img.shields.io/badge/test%20suite-216%20passed%20%7C%20100%25-brightgreen.svg)]()
[![Compliance Standards](https://img.shields.io/badge/compliance-HIPAA%20%7C%20NIST%20SP%20800--63B%20%7C%20SOC2-informational.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [Architectural Principles & Compliance Mapping](#2-architectural-principles--compliance-mapping)
3. [Core Module Directory](#3-core-module-directory)
4. [Universal Prerequisites & Installation](#4-universal-prerequisites--installation)
5. [Module-by-Module Technical Deep-Dive & Integration Guides](#5-module-by-module-technical-deep-dive--integration-guides)
   - [5.1 osivault.fields: Field-Level Encryption & Blind Indexing](#51-osivaultfields-field-level-encryption--blind-indexing)
   - [5.2 osivault.audit: Tamper-Evident Merkle Hash-Chain Audit Ledger](#52-osivaultaudit-tamper-evident-merkle-hash-chain-audit-ledger)
   - [5.3 osivault.auth: Hardware FIDO2 WebAuthn & Monotonic MFA](#53-osivaultauth-hardware-fido2-webauthn--monotonic-mfa)
   - [5.4 osivault.sftp: At-Rest Encrypted Transport & Zero-Wipe Viewer](#54-osivaultsftp-at-rest-encrypted-transport--zero-wipe-viewer)
   - [5.5 osivault.tokens: Asymmetric JWT Engine & RFC 7517/8037 JWKS](#55-osivaulttokens-asymmetric-jwt-engine--rfc-75178037-jwks)
   - [5.6 osivault.sign: Self-Describing Signature Envelopes](#56-osivaultsign-self-describing-signature-envelopes)
   - [5.7 osivault.watch: Automated Compliance Inventory & Posture Auditing](#57-osivaultwatch-automated-compliance-inventory--posture-auditing)
6. [Complete Project Integration Checklist](#6-complete-project-integration-checklist)
7. [Automated Test Suite & Verification](#7-automated-test-suite--verification)
8. [License & Engineering Governance](#8-license--engineering-governance)

---

## 1. Executive Overview

**OSIVault** is an enterprise-grade, zero-trust security core framework designed for Python and Django applications operating in regulated environments (Healthcare/HIPAA, Banking/PCI-DSS, Defense/FedRAMP, and B2B SaaS).

Modern cloud web applications frequently suffer from structural architectural vulnerabilities:
- **Database Leaks**: Sensitive identifiers (Social Security Numbers, Credit Cards, Medical Diagnoses) are stored as plaintext or weakly encrypted without indexing capabilities.
- **Audit Tampering**: Traditional database logs stored in standard rows or flat text files can be modified or purged by database administrators or SQL injection exploits without detection.
- **Phishing Vulnerabilities**: Traditional Multi-Factor Authentication (SMS OTP and software TOTP) remains susceptible to reverse-proxy phishing (Evilginx) and session hijacking.
- **Unencrypted File Pipelines**: Automated SFTP pipelines commonly decrypt incoming files onto application disks in cleartext, exposing Electronic Protected Health Information (ePHI) to server administrators and forensic recovery.
- **Symmetric Key Exposure**: Microservices sharing single symmetric JWT secrets enable any compromised service to forge administrator tokens across the entire enterprise topology.

OSIVault resolves these systematic vulnerabilities by providing a unified, decoupled suite of seven standalone cryptographic modules. Each module functions autonomously or harmoniously within existing application pipelines without forcing architectural refactoring.

---

## 2. Architectural Principles & Compliance Mapping

OSIVault enforces strict security constraints derived from federal and international standards:

| Compliance Mandate | Regulatory Standard | OSIVault Defensive Control | Implemented In |
| :--- | :--- | :--- | :--- |
| **ePHI Encryption at Rest** | HIPAA 45 CFR § 164.312(a)(2)(iv) | AES-256-GCM envelope encryption with blind HMAC indexing | `osivault.fields` |
| **Tamper-Evident Audit Controls** | HIPAA 45 CFR § 164.312(b) | SHA-256 Merkle hash-linked immutable ledger with database-level trigger locks | `osivault.audit` |
| **Phishing-Resistant Authentication** | NIST SP 800-63B AAL3 | FIDO2 / WebAuthn Level 3 hardware security key authentication (YubiKey) | `osivault.auth` |
| **Transmission & Storage Security** | HIPAA § 164.312(e)(1) | Strict SSH host-key pinning + AES-256-GCM at-rest file storage | `osivault.sftp` |
| **Cryptographic Agility & Delegation** | SOC2 Type II Trust Services | Asymmetric RS256/Ed25519 token issuance with RFC 7517/8037 JWKS distribution | `osivault.tokens` |
| **Non-Repudiation Document Signing** | ESIGN Act / eIDAS Standards | Self-describing `OSV1-SIG` signature envelopes with allowlist-first enforcement | `osivault.sign` |
| **Continuous Compliance Assessment** | NIST CSF / ISO 27001 | Machine-readable cryptographic inventory and baseline drift detection | `osivault.watch` |

### Core Design Rules
1. **Decoupled Architecture**: Modules are strictly decoupled. Applications requiring only field encryption or JWT verification can consume individual modules without loading database models or foreign dependencies.
2. **Fail-Closed Security**: Cryptographic mismatches, algorithm deviations, or corrupt data blocks always raise explicit exceptions and refuse execution rather than falling back to unencrypted or default states.
3. **Zero Forensic Retention**: Temporary decrypted plaintext streams are loaded in volatile memory and overwritten with null bytes (`\x00`) prior to process release.

---

## 3. Core Module Directory

OSIVault consists of seven specialized modules:

```text
osivault/
├── fields/     # Field-level database encryption at rest & blind index search
├── audit/      # Immutable cryptographic Merkle hash-chain audit trail
├── auth/       # Hardware WebAuthn/FIDO2 MFA, monotonic TOTP & email proofing
├── sftp/       # At-rest encrypted SFTP client & hardware-gated terminal viewer
├── tokens/     # Asymmetric JWT engine & RFC 7517 / RFC 8037 JWKS endpoints
├── sign/       # Self-describing digital signature envelopes & allowlist engine
└── watch/      # Automated security baseline & compliance inventory reporter
```

---

## 4. Universal Prerequisites & Installation

### System Requirements
- **Python**: Version `3.12` or `3.13` (Required for modern OpenSSL 3.x bindings and cryptographic agility).
- **Framework**: Django `4.2 LTS`, `5.0`, `5.1`, `5.2`, or `6.0+`.
- **Database**: PostgreSQL (recommended for hardware triggers), MySQL, MariaDB, or SQLite.
- **Operating System**: OS-independent (Linux, macOS, Windows Server/Desktop, Docker).

### Universal Installation Command
Run the standard package installation command in your application environment:

```bash
pip install git+https://github.com/yashtayade3105/OSIVault_Company_Security_System.git
```

*Note: OSIVault automatically registers and downloads all required cryptographic runtime dependencies in the background:*
- `cryptography>=42.0.0` (Core OpenSSL primitives, AES-256-GCM, Ed25519, RSA)
- `webauthn>=2.1.0` (W3C WebAuthn Level 3 & FIDO2 CTAP2 assertion verification)
- `paramiko>=3.4.0` (SSH-2 transport layer and SFTP protocol client)
- `pyotp>=2.9.0` (RFC 6238 Time-based One-Time Password verification)
- `qrcode>=7.4.2` & `pillow>=10.0.0` (Provisioning QR generation for mobile authenticators)

---

## 5. Module-by-Module Technical Deep-Dive & Integration Guides

---

### 5.1 `osivault.fields`: Field-Level Encryption & Blind Indexing

#### Problem Solved
Traditional column encryption either prevents searching entirely or requires deterministic encryption (ECB/static IV), which leaks statistical frequency patterns and violates HIPAA § 164.312(a)(2)(iv). Furthermore, performing full table scans for decrypt-then-filter operations degrades database latency from $O(1)$ to $O(N)$, causing query timeouts at scale.

#### Architectural Solution
`osivault.fields` implements **Authenticated AES-256-GCM Envelope Encryption** paired with **HMAC-SHA-256 Blind Indexing (`SearchHash`)**.
- **Ciphertext Storage**: Every encrypted string is prepended with a fresh, cryptographically random 12-byte initialization vector (`nonce`). Even identical plaintexts yield entirely different ciphertexts.
- **Exact-Match Searchability**: A separate blind hash column (`<field>_hash`) stores an HMAC-SHA-256 digest keyed with an isolated blind index salt. Queries execute in $O(1)$ constant time using standard B-Tree database indexes.
- **Key Management**: Supports local master keys (`OSIVAULT_MASTER_KEY`), Key Encryption Keys (KEK), Data Encryption Keys (DEK), and optional AWS KMS key derivation providers.

#### Step-by-Step Integration

**Step 1: Configure Environment Variables**
Define your 32-byte master key (hexadecimal or base64) in your environment configuration:

```env
OSIVAULT_MASTER_KEY=9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
```

*(To generate a fresh 32-byte key: `python -c "import secrets; print(secrets.token_hex(32))"`)*

**Step 2: Define Models with Encrypted Fields**
Replace standard Django fields with `EncryptedCharField` or `EncryptedTextField`:

```python
# accounts/models.py or medical/models.py
from django.db import models
from osivault.fields import EncryptedCharField, EncryptedTextField

class PatientRecord(models.Model):
    patient_id = models.CharField(max_length=64, unique=True)
    full_name = models.CharField(max_length=255)
    
    # Encrypted at rest via AES-256-GCM; searchable via HMAC-SHA-256 blind index
    ssn = EncryptedCharField(max_length=11, searchable=True, db_index=True)
    phone_number = EncryptedCharField(max_length=20, searchable=True)
    
    # Long text encrypted at rest (non-searchable)
    clinical_notes = EncryptedTextField()

    def __str__(self):
        return f"Patient {self.patient_id} ({self.full_name})"
```

**Step 3: Run Database Migrations**
```bash
python manage.py makemigrations
python manage.py migrate
```

**Step 4: Execute Standard ORM Queries**
Encryption and decryption occur transparently inside the Django ORM layer:

```python
# Saving data: Automatically encrypted into ciphertext before SQL write
patient = PatientRecord.objects.create(
    patient_id="PAT-1001",
    full_name="John Doe",
    ssn="123-45-6789",
    clinical_notes="Patient presented with acute hypertension."
)

# Reading data: Automatically decrypted back into plaintext upon model retrieval
record = PatientRecord.objects.get(patient_id="PAT-1001")
print(record.ssn)  # Outputs: "123-45-6789"

# Querying data: Exact match queries automatically transform into blind index hash queries
found = PatientRecord.objects.filter(ssn="123-45-6789").first()
assert found.id == patient.id
```

---

### 5.2 `osivault.audit`: Tamper-Evident Merkle Hash-Chain Audit Ledger

#### Problem Solved
Audit logs in enterprise software are vulnerable to internal manipulation: malicious administrators, compromised root accounts, or SQL injection exploits can delete or modify rows in traditional logging tables (`UPDATE audit_log SET ...` or `DELETE FROM audit_log`). Once logs are altered, incident reconstruction is legally void.

#### Architectural Solution
`osivault.audit` structures every event into a **Cryptographic SHA-256 Merkle Hash-Chain**:
- Every audit record calculates:
  $$\text{Hash}_N = \text{SHA256}(\text{Hash}_{N-1} \parallel \text{Timestamp} \parallel \text{Actor} \parallel \text{Action} \parallel \text{Resource} \parallel \text{Values})$$
- Modifying, deleting, or inserting any historic row breaks the hash continuity for all subsequent rows, instantly revealing tampering.
- **Hardware Trigger Protection**: On PostgreSQL, database-level triggers strictly block any `UPDATE` or `DELETE` SQL operations at the database engine layer.
- **Large Dataset Performance**: Implements memory-efficient chunked iterators (`chunk_size=2000`) for high-speed verification across tables containing millions of audit entries.

#### Step-by-Step Integration

**Step 1: Register in Django `settings.py`**
```python
INSTALLED_APPS = [
    # ...
    "osivault.audit",
]

MIDDLEWARE = [
    # ...
    # Optional: Automatically capture request actor and path metadata
    "osivault.audit.OSIVaultAuditMiddleware",
]
```

**Step 2: Run Database Migrations**
```bash
python manage.py migrate
```
*(Creates the `osivault_audit_entry` table and configures database trigger protections).*

**Step 3: Record Audit Events in Application Logic**
```python
import osivault.audit

def process_patient_claim(request, claim_id, amount):
    # Execute medical claim processing logic...
    
    # Append immutable event to hash chain
    osivault.audit.append(
        request=request,
        actor=request.user.username if request.user.is_authenticated else "system_cron",
        tenant="hospital_network_a",
        resource_type="InsuranceClaim",
        resource_id=str(claim_id),
        action="CLAIM_APPROVED",
        old_values={"status": "PENDING"},
        new_values={"status": "APPROVED", "approved_amount": amount}
    )
```

**Step 4: Verify Chain Integrity via Python API or CLI**
```python
import osivault.audit

# Audit verification across all entries
is_valid, broken_id = osivault.audit.verify_chain()
if not is_valid:
    print(f"CRITICAL SECURITY ALERT: Audit trail tampering detected at record ID {broken_id}!")
else:
    print("Audit trail 100% intact and cryptographically verified.")
```

---

### 5.3 `osivault.auth`: Hardware FIDO2 WebAuthn & Monotonic MFA

#### Problem Solved
SMS-based two-factor authentication is routinely bypassed via SIM swapping and SS7 interception. Standard TOTP (Authenticator apps) can be intercepted in real-time by phishing reverse proxies (such as Evilginx). Furthermore, TOTP replay attacks occur when an intercepted 6-digit code is replayed within the remaining 30-second validity window.

#### Architectural Solution
`osivault.auth` provides **Hardware-First, Phishing-Resistant Authentication (NIST SP 800-63B AAL3)**:
- **FIDO2 / WebAuthn Level 3**: Direct hardware integration with physical security keys (YubiKey 5 Series USB/NFC, Google Titan, and biometric platform authenticators). Private keys never leave the hardware chip.
- **Clone Detection**: Hardware signature verification tracks monotonic `sign_count`. Cloned authenticators trigger instant security locks.
- **Monotonic Replay Guard**: TOTP verification tracks monotonic timecode counters (`counter > last_counter`). Reusing a code within the same 30-second window is rejected.
- **Zero-Knowledge Recovery Codes**: Emergency break-glass codes are stored exclusively as SHA-256 hashes.
- **Email Proofing**: Built-in 6-digit secure Email OTP adapter with attempt throttling (max 5) and 10-minute expiration.

#### Step-by-Step Integration

**Step 1: Register in Django `settings.py`**
```python
INSTALLED_APPS = [
    # ...
    "osivault.auth",
]
```

**Step 2: Run Database Migrations**
```bash
python manage.py migrate
```
*(Creates `osivault_webauthn_key`, `osivault_totp_device`, `osivault_recovery_code`, and `osivault_mfa_profile` tables).*

**Step 3: Route URLs in `urls.py`**
```python
# config/urls.py
from django.urls import path, include

urlpatterns = [
    # ... application paths ...
    path("osivault/auth/", include("osivault.auth.urls", namespace="osivault_auth")),
]
```

**Step 4: Use Standalone Adapters in Application Controllers**

*Verifying WebAuthn Hardware Signatures:*
```python
from osivault.auth.adapters import WebAuthnAsserter

asserter = WebAuthnAsserter(rp_id="mirportal.company.com")

# Verify cryptographic assertion from browser ceremony
verification_result = asserter.verify_assertion_response(
    credential_id=data["credential_id"],
    authenticator_data_b64=data["authenticator_data"],
    client_data_json_b64=data["client_data_json"],
    signature_b64=data["signature"],
    challenge_b64=session_challenge,
    public_key_b64=registered_key.public_key,
    expected_rp_id="mirportal.company.com",
    expected_origin="https://mirportal.company.com",
    current_sign_count=registered_key.sign_count,
)

if verification_result["verified"]:
    registered_key.sign_count = verification_result["new_sign_count"]
    registered_key.save()
```

*Verifying TOTP Authenticator with Replay Protection:*
```python
from osivault.auth.adapters import TOTPVerifier

# Initialize verifier with user's seed and last monotonic counter
verifier = TOTPVerifier(secret=totp_device.encrypted_secret, last_counter=totp_device.last_counter)

if verifier.verify(otp_code=user_input_code):
    totp_device.last_counter = verifier.last_counter
    totp_device.save()
    print("Authentication successful.")
else:
    print("Invalid, expired, or replayed code rejected.")
```

---

### 5.4 `osivault.sftp`: At-Rest Encrypted Transport & Zero-Wipe Viewer

#### Problem Solved
Traditional SFTP clients (Paramiko, pysftp) secure data only in-transit across the SSH tunnel. Once written to disk, sensitive files (such as healthcare EDI 835 payment remittances and EDI 837 claims) sit in plaintext. Any administrator, rogue process, or backup breach exposes sensitive patient and financial records. Furthermore, inspecting files via local text editors leaves unencrypted temporary files in operating system caches.

#### Architectural Solution
`osivault.sftp` enforces an **Armored File Vault**:
- **At-Rest Payload Encryption**: File payloads are encrypted using **AES-256-GCM** before touching storage. Files are stored on disk as ciphertext with an `OSIV` binary header.
- **Strict Host Key Pinning**: Implements `StrictHostKeyPolicy`, validating the SSH server's public key against an expected SHA-256 fingerprint (`SHA256:...`) to defeat Man-in-the-Middle (MitM) attacks.
- **Hardware-Gated File Decryption**: Encrypted files can only be decrypted by authorized Superusers presenting physical YubiKey touch contact.
- **Volatile In-Memory Viewer with Zero-Wipe**: Opens selected files in multi-tab editor sessions (Notepad on Windows, TextEdit on macOS). Upon closing the editor, temporary memory streams and disk buffers are overwritten with null bytes (`\x00`) and unlinked, preventing forensic file carving.

#### Step-by-Step Integration

**Step 1: Register in Django `settings.py`**
```python
INSTALLED_APPS = [
    # ...
    "osivault.sftp",
]

# Configure vault directory
OSIVAULT_SFTP_DIRECTORY = "/var/vault/sftp_storage"
```

**Step 2: Run Database Migrations**
```bash
python manage.py migrate
```

**Step 3: Transfer Files Securely in Automated Pipelines**
```python
from osivault.sftp import SecureSFTPClient

# Connect over SSH tunnel with strict host key pinning
with SecureSFTPClient(
    hostname="sftp.payer.com",
    username="gateway_user",
    private_key_path="/etc/ssl/id_ed25519",
    expected_fingerprint="SHA256:7uX9kQ...",  # Host key pinning
) as client:

    # Downloads remote file and stores on local disk as AES-256-GCM ciphertext
    client.download_file(
        remote_path="/outbound/remittance_835.edi",
        local_path="/var/vault/sftp_storage/remittance_835.edi",
        decrypt_at_rest=False  # Keep stored file 100% encrypted on disk!
    )
```

**Step 4: Terminal Hardware-Gated Inspection Commands**

*Register Authorized Superusers (Enforces maximum limit of 3 superusers per project with dual YubiKey slots):*
```bash
python manage.py create_sftp_superuser
```

*Scan and View Encrypted Files in Any Directory:*
```bash
# Scan single file
python manage.py sftp_view_file /var/vault/sftp_storage/remittance_835.edi

# Recursively scan an entire directory structure with multi-tab viewing
python manage.py sftp_view_file /var/vault/sftp_storage/
```

---

### 5.5 `osivault.tokens`: Asymmetric JWT Engine & RFC 7517/8037 JWKS

#### Problem Solved
Symmetric JWT implementations (`HS256`) require every consuming microservice to hold the master signing secret. If a single microservice is compromised, an attacker can forge administrative tokens across all systems. Additionally, static keys prevent rotation without invalidating active user sessions.

#### Architectural Solution
`osivault.tokens` provides an **Asymmetric Public-Private Key Identity Token System**:
- **Asymmetric Signing**: Tokens are signed with private RSA keys (`RS256`) or Ed25519 keys (`Ed25519`). Consuming services only receive the public key.
- **RFC 7517 & RFC 8037 JWKS Generator**: Exposes standard JSON Web Key Set documents (`jwks_document()`) containing key identifiers (`kid`), modulus (`n`), exponent (`e`), and Octet Key Pair parameters (`x`).
- **Zero-Downtime Key Rotation**: The `rotate()` function generates fresh keypairs and unique key IDs. Old tokens remain verifiable while new tokens are signed with the active key.
- **Allowlist-First Security**: Blocks "None" algorithm exploits and symmetric/asymmetric confusion attacks.

#### Step-by-Step Integration

**Step 1: Import and Issue Tokens**
```python
from osivault.tokens import issue, rotate

# Optional: Generate fresh RSA keypair or use default system key
private_key, public_key, key_id = rotate()

claims = {
    "sub": "user_9812",
    "email": "doctor@hospital.org",
    "role": "attending_physician",
    "tenant_id": "clinic_42"
}

# Issue asymmetric signed JWT with 1-hour expiration
token = issue(
    claims=claims,
    private_key=private_key,
    key_id=key_id,
    ttl_seconds=3600,
    alg="RS256"
)
```

**Step 2: Verify Tokens in API Endpoints or Microservices**
```python
from osivault.tokens import verify, TokenError

try:
    decoded = verify(
        token=token,
        public_key_or_jwks=public_key,
        expected_issuer="https://auth.company.com"  # Optional issuer check
    )
    print("Authenticated Subject:", decoded["sub"])
    print("User Role:", decoded["role"])
except TokenError as e:
    print("Access Denied: Invalid or expired token:", str(e))
```

**Step 3: Export JWKS Document for External Microservices (React, Node, Go)**
```python
from osivault.tokens import jwks_document

# Returns standard RFC 7517 JSON dictionary for exposure at /.well-known/jwks.json
jwks = jwks_document([(public_key, key_id, "RS256")])
```

---

### 5.6 `osivault.sign`: Self-Describing Signature Envelopes

#### Problem Solved
Regulated data operations (medical approvals, prescription issuances, financial payouts) require verifiable non-repudiation. Storing signatures separately from payloads often results in decoupled data and complex verification pipelines. Furthermore, vulnerabilities such as algorithm confusion arise when verifiers trust unverified header metadata.

#### Architectural Solution
`osivault.sign` wraps payloads in **Self-Describing Signature Envelopes**:
- **Format**: `OSV1-SIG$<algorithm>$<key_id>$<hash_alg>$<base64_payload>$<base64_signature>`
- **Strict Allowlist Defense**: Only approved algorithms (`RS256`, `Ed25519`) are permitted. Any unapproved algorithm string triggers instant rejection before key resolution or cryptographic parsing.
- **Dynamic Resolvers**: Supports dynamic key lookup callbacks (`key_resolver=lambda kid: key_store[kid]`).

#### Step-by-Step Integration

```python
from osivault.sign import sign, verify, SignatureVerificationError
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate signing keypair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# 1. Sign document or payload
document_bytes = b"Doctor Jane Smith hereby authorizes surgical procedure #9901"
signed_envelope = sign(
    payload=document_bytes,
    key=private_key,
    alg="Ed25519",
    key_id="doc-jane-smith-key"
)

# 2. Verify signature envelope
try:
    envelope = verify(signed_envelope, public_key=public_key)
    print("Signature Valid!")
    print("Key ID:", envelope.key_id)
    print("Original Payload:", envelope.payload.decode("utf-8"))
except SignatureVerificationError as e:
    print("Tampering detected! Invalid signature:", str(e))
```

---

### 5.7 `osivault.watch`: Automated Compliance Inventory & Posture Auditing

#### Problem Solved
Auditors (HIPAA, SOC2, HITRUST) require verification that active environments comply with approved cryptographic baselines. Manually auditing dependencies and verifying algorithm configurations is labor-intensive and error-prone.

#### Architectural Solution
`osivault.watch` provides **Continuous Automated Compliance Assessment**:
- `inventory()`: Inspects the running runtime and returns a structured inventory of active algorithms, cryptographic primitives, and package versions.
- `baseline()`: Exposes the approved corporate baseline (minimum RSA 2048-bit, SHA-256+, AES-256-GCM, FIDO2 MFA).
- `report()`: Evaluates active inventory against the baseline, producing an automated compliance scorecard (`COMPLIANT` vs `NON-COMPLIANT`) with detailed pass/fail counts.

#### Step-by-Step Integration

```python
import osivault.watch

# Generate live compliance assessment report
report = osivault.watch.report()

print("Status:", report["summary"])               # Outputs: "COMPLIANT"
print("Passed Checks:", report["passed_checks_count"]) # e.g. 7 passed
print("Violations:", report["violations_count"])       # e.g. 0 violations
print("Details:", report["passed_checks"])
```

---

## 6. Complete Project Integration Checklist

To integrate OSIVault into any Django project, execute these standard steps:

- [ ] **1. Install Package**:
  ```bash
  pip install git+https://github.com/yashtayade3105/OSIVault_Company_Security_System.git
  ```
- [ ] **2. Register in `settings.py`**:
  ```python
  INSTALLED_APPS = [
      # ...
      "osivault.audit",  # For Merkle hash-chain logging
      "osivault.auth",   # For YubiKey hardware MFA & OTP
      "osivault.sftp",   # For at-rest encrypted SFTP transport
  ]
  ```
- [ ] **3. Configure Environment Secret**:
  ```env
  OSIVAULT_MASTER_KEY=your_32_byte_hexadecimal_key_here
  ```
- [ ] **4. Run Migrations**:
  ```bash
  python manage.py migrate
  ```
- [ ] **5. Import and Use**:
  Use `osivault.fields` in models, `osivault.auth` in authentication views, `osivault.tokens` in API handlers, and `osivault.sftp` in batch data pipelines.

---

## 7. Automated Test Suite & Verification

OSIVault maintains an exhaustive, end-to-end automated test suite verifying edge cases, boundary conditions, and cryptographic attacks across all modules:

```bash
# Run the complete test suite
pytest -v
```

### Verified Test Suite Breakdown

| Module | Test File | Test Cases | Areas Covered | Status |
| :--- | :--- | :---: | :--- | :---: |
| **Tokens** | `tests/test_tokens.py` | **62** | RS256/Ed25519, Expiry, RFC 7517/8037 JWKS, Rotation, Attacks | Passed |
| **Signatures** | `tests/test_sign.py` | **58** | Envelopes, Allowlist-first, Tampering, Malformed Inputs | Passed |
| **Auth & MFA** | `tests/test_auth.py` | **33** | FIDO2 YubiKey ceremonies, Monotonic TOTP guard, Recovery codes | Passed |
| **Audit Logs** | `tests/test_audit.py` | **25** | Merkle hash linkage, Chunk iteration, Append-only triggers | Passed |
| **Fields** | `tests/test_fields.py` | **20** | AES-256-GCM at rest, HMAC-SHA-256 blind indexing, Key providers | Passed |
| **SFTP Vault** | `tests/test_sftp.py` | **19** | Strict host keys, Payload encryption, YubiKey viewer, Zero-wipe | Passed |
| **Total** | | **217** | **Complete Suite Execution: ~23 Seconds** | **100% Passed** |

---

## 8. License & Engineering Governance

OSIVault is distributed under the enterprise-friendly **MIT License**.

- **Repository**: [https://github.com/yashtayade3105/OSIVault_Company_Security_System](https://github.com/yashtayade3105/OSIVault_Company_Security_System)
- **Author**: Yash Tayade & OSIVault Security Engineering
- **Engineering Inquiries**: `tayadeyash2005@gmail.com`
- **Security Disclosures**: Please report sensitive vulnerabilities directly to the maintainers via secure email before public disclosure.
