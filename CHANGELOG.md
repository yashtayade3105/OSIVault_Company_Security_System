# Changelog

All notable changes to OSIVault will be documented in this file.
The format is based on Keep a Changelog and this project adheres to Semantic Versioning.
OSIVault is consumed by git tag; see docs/charter.md for the pin policy.

## [Unreleased]

### Added
- `osivault.fields`: AES-256-GCM envelope encryption (`$OSV1$`), pluggable KMS key providers, DEK key rotation (`rotate_dek`), `SearchHash` blind index hashing, and Django encrypted model fields (`EncryptedCharField`, `EncryptedTextField`, `EncryptedJSONField`).
- `osivault.audit`: Keyed HMAC-SHA-256 Merkle chain audit logs, PostgreSQL advisory locks (`pg_advisory_xact_lock`), row-level DB immutability triggers (`BEFORE UPDATE OR DELETE`), `verify_entry`, `verify_chain`, `rotate_key`, and signed checkpoints.
- `osivault.sign`: Self-describing `OSV1-SIG` signature envelopes with allowlist-first verification supporting RS256 and Ed25519 signature schemes.
- `osivault.tokens`: Crypto-agile JWT issuance (`issue`), verification (`verify`), and RFC 7517 compliant JWKS exporter (`jwks_document`).
- `osivault.auth`: Replay-guarded TOTP verifier, WebAuthn / FIDO2 authentication adapters, and single-use SHA-256 emergency recovery codes.
- `osivault.watch`: Security posture auditor returning machine-readable JSON compliance reports (`inventory()`, `baseline()`, `report()`).

## [0.1.0] - 2026-09-08
- Initial release skeleton of OSIVault core.
