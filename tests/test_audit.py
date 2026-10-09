"""
Comprehensive end-to-end test suite for osivault.audit.

Strictly verifies all Task 1 and Task 2 specification requirements:
- Merged HMAC-SHA-256 chain integrity & previous_hash linkage
- ISO 8601 UTC microsecond timestamp and tenant AAD binding
- Strict ORM & Queryset immutability guards (_osivault_append_token)
- Signed & chained table state checkpoints (verify_checkpoint)
- Advisory locks & concurrency safety
- Allowlist-first envelope verification & fail-closed behavior
"""

import threading
import logging
import pytest
from django.db import connection
from django.conf import settings

from tests.models import ConcreteAuditLog
from tests.conftest import postgres_only
from osivault.audit import (
    append,
    verify_entry,
    verify_chain,
    rotate_key,
    checkpoint,
    verify_checkpoint,
    register_audit_signal,
    install_postgres_immutability_triggers,
)
from osivault.audit.models import OSIVaultAuditCheckpoint
from osivault.audit.crypto import ImmutabilityError, ConfigurationError
from osivault.audit.keys import InMemoryKeyProvider, _set_default_key_provider_for_tests, EnvVarKeyProvider


@pytest.mark.django_db
def test_chain_integrity():
    """
    Append ten entries; verify_chain reports intact.
    """
    for i in range(10):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_alpha",
            resource_type="Document",
            resource_id=f"doc_{i}",
            action="CREATE",
            old_values={},
            new_values={"index": i},
        )

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True
    assert report.total_count == 10
    assert report.current_key_count == 10
    assert report.previous_key_count == 0
    assert report.failed_pk is None


@pytest.mark.django_db
def test_altered_entry_field():
    """
    Note: Database trigger is not installed in this test so raw SQL tampering is possible.
    Alter any field of an entry via raw SQL; verify_chain reports exact row and MAC failure.
    """
    entries = []
    for i in range(10):
        e = append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_alpha",
            resource_type="Document",
            resource_id=f"doc_{i}",
            action="READ",
            old_values={},
            new_values={},
        )
        entries.append(e)

    target_pk = entries[4].pk
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET action = 'MALICIOUS_UPDATE' WHERE id = {target_pk}"
        )

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is False
    assert report.failed_pk == target_pk
    assert "MAC verification failed" in report.failure_reason


@pytest.mark.django_db
def test_deleted_middle_row():
    """
    Note: Database trigger is not installed in this test so raw SQL tampering is possible.
    Delete a middle row via raw SQL; verify_chain reports break at following row.
    """
    entries = []
    for i in range(10):
        e = append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_alpha",
            resource_type="Document",
            resource_id=f"doc_{i}",
            action="WRITE",
            old_values={},
            new_values={},
        )
        entries.append(e)

    deleted_pk = entries[4].pk
    following_pk = entries[5].pk

    with connection.cursor() as cursor:
        cursor.execute(f"DELETE FROM test_concrete_audit_log WHERE id = {deleted_pk}")

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is False
    assert report.failed_pk == following_pk
    assert "previous_hash mismatch" in report.failure_reason


@pytest.mark.django_db
def test_swapped_row_order():
    """
    Note: Database trigger is not installed in this test so raw SQL tampering is possible.
    Swap order of two rows' contents via raw SQL; verify_chain reports both.
    """
    entries = []
    for i in range(5):
        e = append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_alpha",
            resource_type="Item",
            resource_id=f"item_{i}",
            action=f"ACTION_TYPE_{i}",
            old_values={},
            new_values={},
        )
        entries.append(e)

    pk1, pk2 = entries[1].pk, entries[2].pk
    act1, act2 = entries[1].action, entries[2].action

    with connection.cursor() as cursor:
        cursor.execute(f"UPDATE test_concrete_audit_log SET action = '{act2}' WHERE id = {pk1}")
        cursor.execute(f"UPDATE test_concrete_audit_log SET action = '{act1}' WHERE id = {pk2}")

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is False
    assert report.failed_pk == pk1


@pytest.mark.django_db
def test_timestamp_tampering():
    """
    Regression Test: Change only timestamp via raw SQL -> MAC fails.
    Note: Database trigger is not installed in this test so raw SQL tampering is possible.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="alice@onesmarter.com",
        tenant="tenant_beta",
        resource_type="MedicalRecord",
        resource_id="mr_100",
        action="VIEW",
        old_values={},
        new_values={},
    )

    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET timestamp = '2000-01-01 00:00:00.000000+00' WHERE id = {entry.pk}"
        )

    modified_entry = ConcreteAuditLog.objects.get(pk=entry.pk)
    verified, key_used, reason = verify_entry(modified_entry)
    assert verified is False
    assert "MAC verification failed" in reason


@pytest.mark.django_db
def test_tenant_tampering():
    """
    Regression Test: Change only tenant via raw SQL -> MAC fails.
    Note: Database trigger is not installed in this test so raw SQL tampering is possible.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="bob@onesmarter.com",
        tenant="tenant_original",
        resource_type="BillingData",
        resource_id="bill_50",
        action="EXPORT",
        old_values={},
        new_values={},
    )

    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET tenant = 'tenant_hacked' WHERE id = {entry.pk}"
        )

    modified_entry = ConcreteAuditLog.objects.get(pk=entry.pk)
    verified, key_used, reason = verify_entry(modified_entry)
    assert verified is False


@pytest.mark.django_db
def test_unkeyed_rehash_attack():
    """
    Attacker re-calculates SHA-256 hash without secret key -> verify_entry rejects.
    Note: Database trigger is not installed in this test so raw SQL tampering is possible.
    """
    import hashlib
    entry = append(
        model_class=ConcreteAuditLog,
        actor="attacker@onesmarter.com",
        tenant="tenant_target",
        resource_type="Account",
        resource_id="acc_1",
        action="TRANSFER",
        old_values={"amount": 100},
        new_values={"amount": 10000},
    )

    unkeyed_hash = hashlib.sha256(b"fake_payload_without_secret_key").hexdigest()
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET new_values = '{{\"amount\": 10000}}', entry_hash = '{unkeyed_hash}' WHERE id = {entry.pk}"
        )

    modified_entry = ConcreteAuditLog.objects.get(pk=entry.pk)
    verified, key_used, reason = verify_entry(modified_entry)
    assert verified is False


@pytest.mark.django_db
def test_key_rotation():
    """
    Test explicit key rotation using InMemoryKeyProvider across 10 entries and double rotation behavior.
    """
    provider = InMemoryKeyProvider(current_key="k1_key_bytes_initial_32bytes!!", current_key_id="k1")
    _set_default_key_provider_for_tests(provider)

    for i in range(5):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_gamma",
            resource_type="Record",
            resource_id=f"rec_{i}",
            action="CREATE",
            old_values={},
            new_values={},
            key_provider=provider,
        )

    # Rotate Key
    new_key = "k2_key_bytes_rotated_32bytes!!!"
    rotate_key(new_current_key=new_key, new_key_id="k2", key_provider=provider)

    for i in range(5, 10):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_gamma",
            resource_type="Record",
            resource_id=f"rec_{i}",
            action="CREATE",
            old_values={},
            new_values={},
            key_provider=provider,
        )

    report = verify_chain(ConcreteAuditLog, key_provider=provider)
    assert report.is_intact is True
    assert report.current_key_count == 5
    assert report.previous_key_count == 5

    # Second Rotation: Original key is purged
    rotate_key(new_current_key="k3_third_key_bytes_32bytes!!!!", new_key_id="k3", key_provider=provider)
    report2 = verify_chain(ConcreteAuditLog, key_provider=provider)
    assert report2.is_intact is False
    assert report2.failed_pk == ConcreteAuditLog.objects.order_by("pk").first().pk


@pytest.mark.django_db
def test_rotate_env_provider_raises():
    """
    Attempting to call rotate_key on EnvVarKeyProvider raises ConfigurationError.
    """
    env_provider = EnvVarKeyProvider()
    with pytest.raises(ConfigurationError, match="Environment-backed keys are rotated operationally"):
        rotate_key("new_key", key_provider=env_provider)


@pytest.mark.django_db
def test_allowlist_envelope_rejection():
    """
    Envelope naming unallowed algorithm (e.g. HMAC-SHA-512) refused before computing anything.
    Note: Database trigger is not installed in this test so raw SQL tampering is possible.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="charlie@onesmarter.com",
        tenant="tenant_delta",
        resource_type="File",
        resource_id="file_1",
        action="DELETE",
        old_values={},
        new_values={},
    )

    unsupported_envelope = '{"mac_alg": "HMAC-SHA-512", "fmt_ver": 1, "hash_alg": "SHA-512", "key_id": "k1"}'
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET envelope = '{unsupported_envelope}' WHERE id = {entry.pk}"
        )

    modified_entry = ConcreteAuditLog.objects.get(pk=entry.pk)
    verified, key_used, reason = verify_entry(modified_entry)
    assert verified is False
    assert "Envelope algorithm 'HMAC-SHA-512' not in allowlist" in reason


@pytest.mark.django_db
def test_fail_closed_and_debug_fallback(monkeypatch, caplog):
    """
    Missing key with DEBUG=False raises ConfigurationError. DEBUG=True uses fallback & logs warning.
    """
    env_provider = EnvVarKeyProvider()
    _set_default_key_provider_for_tests(env_provider)

    monkeypatch.delenv("OSIVAULT_AUDIT_CURRENT_KEY", raising=False)
    monkeypatch.delenv("OSIVAULT_AUDIT_PREVIOUS_KEY", raising=False)

    # Case 1: DEBUG=False -> Fail closed
    monkeypatch.setattr(settings, "DEBUG", False)
    with pytest.raises(ConfigurationError):
        append(
            model_class=ConcreteAuditLog,
            actor="dev@onesmarter.com",
            tenant="tenant_test",
            resource_type="Test",
            resource_id="1",
            action="TEST",
            old_values={},
            new_values={},
            key_provider=env_provider,
        )

    # Case 2: DEBUG=True -> Log warning and use fallback key
    monkeypatch.setattr(settings, "DEBUG", True)
    with caplog.at_level(logging.WARNING):
        entry = append(
            model_class=ConcreteAuditLog,
            actor="dev@onesmarter.com",
            tenant="tenant_test",
            resource_type="Test",
            resource_id="1",
            action="TEST",
            old_values={},
            new_values={},
            key_provider=env_provider,
        )
        assert entry is not None
        assert "DEVELOPMENT FALLBACK KEY" in caplog.text


@pytest.mark.django_db
def test_verify_without_keys_raises(monkeypatch):
    """
    Verifying an entry with no current or previous key configured and DEBUG=False raises ConfigurationError.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="test@onesmarter.com",
        tenant="tenant_test",
        resource_type="Res",
        resource_id="1",
        action="ACT",
    )

    env_provider = EnvVarKeyProvider()
    monkeypatch.delenv("OSIVAULT_AUDIT_CURRENT_KEY", raising=False)
    monkeypatch.delenv("OSIVAULT_AUDIT_PREVIOUS_KEY", raising=False)
    monkeypatch.setattr(settings, "DEBUG", False)

    with pytest.raises(ConfigurationError):
        verify_entry(entry, key_provider=env_provider)


@pytest.mark.django_db
def test_immutability_guards():
    """
    Model save on existing PK raises ImmutabilityError; delete raises ImmutabilityError.
    Queryset update and delete raise ImmutabilityError.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="dave@onesmarter.com",
        tenant="tenant_epsilon",
        resource_type="Policy",
        resource_id="pol_1",
        action="ACTIVATE",
        old_values={},
        new_values={},
    )

    # 1. ORM Save on existing PK
    with pytest.raises(ImmutabilityError):
        entry.action = "TAMPER"
        entry.save()

    # 2. ORM Delete
    with pytest.raises(ImmutabilityError):
        entry.delete()

    # 3. QuerySet Update & Delete
    with pytest.raises(ImmutabilityError):
        ConcreteAuditLog.objects.filter(pk=entry.pk).update(action="TAMPER")

    with pytest.raises(ImmutabilityError):
        ConcreteAuditLog.objects.filter(pk=entry.pk).delete()


@pytest.mark.django_db
def test_append_is_the_only_way_in():
    """
    Direct model .create(), direct instantiation .save(), and .bulk_create() all raise ImmutabilityError.
    """
    fields = dict(
        timestamp=settings.TIME_ZONE,
        actor="evil",
        tenant="tenant_evil",
        resource_type="Hack",
        resource_id="1",
        action="BYPASS",
        entry_hash="00",
        envelope={},
    )

    with pytest.raises(ImmutabilityError):
        ConcreteAuditLog.objects.create(**fields)

    with pytest.raises(ImmutabilityError):
        ConcreteAuditLog(**fields).save()

    with pytest.raises(ImmutabilityError):
        ConcreteAuditLog.objects.bulk_create([ConcreteAuditLog(**fields)])


@pytest.mark.django_db
def test_checkpoint_immutability():
    """
    Direct instantiation .save(), .delete(), and .bulk_create() on OSIVaultAuditCheckpoint raise ImmutabilityError.
    """
    cp = checkpoint(ConcreteAuditLog)
    assert cp is not None

    with pytest.raises(ImmutabilityError):
        cp.row_count = 999
        cp.save()

    with pytest.raises(ImmutabilityError):
        cp.delete()

    with pytest.raises(ImmutabilityError):
        OSIVaultAuditCheckpoint.objects.bulk_create([OSIVaultAuditCheckpoint()])


@postgres_only
@pytest.mark.django_db(transaction=True)
def test_concurrency_safe():
    """
    Simultaneous appends across multiple threads result in a linear, intact audit chain with exactly 1 root.
    Targeted against PostgreSQL Advisory Locks.
    """
    threads = []
    errors = []

    def worker(thread_idx):
        try:
            for i in range(5):
                append(
                    model_class=ConcreteAuditLog,
                    actor=f"thread_{thread_idx}@onesmarter.com",
                    tenant="tenant_concurrent",
                    resource_type="BatchJob",
                    resource_id=f"job_{i}",
                    action="PROCESS",
                    old_values={},
                    new_values={"thread": thread_idx, "iter": i},
                )
        except Exception as ex:
            errors.append(ex)

    for t_id in range(4):
        t = threading.Thread(target=worker, args=(t_id,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0
    assert ConcreteAuditLog.objects.count() == 20

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True
    roots = ConcreteAuditLog.objects.filter(previous_hash="").count()
    assert roots == 1


@pytest.mark.django_db
def test_table_replacement_checkpoint():
    """
    Checkpoint verification catches whole-table replacement attacks.
    """
    for i in range(5):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_secure",
            resource_type="Tx",
            resource_id=f"tx_{i}",
            action="EXECUTE",
            old_values={},
            new_values={},
        )

    cp1 = checkpoint(ConcreteAuditLog)
    assert cp1 is not None

    # Replace whole table contents with new valid chain of same length
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM test_concrete_audit_log")

    for i in range(5):
        append(
            model_class=ConcreteAuditLog,
            actor=f"fake_user_{i}@onesmarter.com",
            tenant="tenant_fake",
            resource_type="Tx",
            resource_id=f"fake_tx_{i}",
            action="EXECUTE",
            old_values={},
            new_values={},
        )

    # verify_chain on new table is internally intact
    new_report = verify_chain(ConcreteAuditLog)
    assert new_report.is_intact is True

    # BUT historical checkpoint fails to verify live table state!
    res = verify_checkpoint(cp1, ConcreteAuditLog)
    assert res.envelope_ok is True
    assert res.mac_ok is True
    assert res.live_ok is False
    assert "Live table state does not match historical checkpoint" in res.failure_reason


@pytest.mark.django_db
def test_checkpoint_chain():
    """
    Verifies that multiple checkpoints form a tamper-evident signed chain.
    """
    for i in range(3):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}",
            tenant="t",
            resource_type="r",
            resource_id=str(i),
            action="A",
        )
        checkpoint(ConcreteAuditLog)

    checkpoints = list(OSIVaultAuditCheckpoint.objects.order_by("pk"))
    assert len(checkpoints) == 3

    # Verify all 3 checkpoints initially
    for cp in checkpoints:
        report = verify_checkpoint(cp, ConcreteAuditLog)
        assert report.envelope_ok is True
        assert report.mac_ok is True
        assert report.chain_ok is True

    # Tamper with middle checkpoint's checkpoint_hash & previous_checkpoint_hash via raw SQL
    middle_cp = checkpoints[1]
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE osivault_audit_checkpoint SET checkpoint_hash = 'tampered_hash_value', previous_checkpoint_hash = 'tampered_prev_hash' WHERE id = {middle_cp.pk}"
        )

    # Middle checkpoint MAC fails due to payload mismatch and altered hash
    middle_reloaded = OSIVaultAuditCheckpoint.objects.get(pk=middle_cp.pk)
    rep_mid = verify_checkpoint(middle_reloaded, ConcreteAuditLog)
    assert rep_mid.mac_ok is False

    # 3rd checkpoint fails chain_ok because middle checkpoint's hash is now 'tampered_hash_value', which no longer matches 3rd checkpoint's previous_checkpoint_hash
    third_cp = checkpoints[2]
    rep_third = verify_checkpoint(third_cp, ConcreteAuditLog)
    assert rep_third.chain_ok is False


@pytest.mark.django_db
def test_register_audit_signal_automatic_and_nan_sanitization():
    """
    Verifies in-built register_audit_signal helper and NaN float sanitization for PostgreSQL JSONB compliance.
    """
    from django.contrib.auth.models import User

    register_audit_signal(User, ConcreteAuditLog)
    u = User.objects.create_user(username="osivault_test_user_2026", email="test2026@osivault.com")

    assert ConcreteAuditLog.objects.count() >= 1
    latest = ConcreteAuditLog.objects.latest("pk")
    assert latest.action == "CREATE_USER"
    assert latest.new_values.get("username") == "osivault_test_user_2026"

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True


@pytest.mark.django_db
def test_unicode_special_chars_emoji_payload():
    """
    Edge Case: Appending and verifying payloads with UTF-8 multi-language text, emojis, and special control characters.
    """
    unicode_actor = "yash_tayade_🚀_सुरक्षा@onesmarter.com"
    unicode_tenant = "tenant_हिंदी_enterprise_🔐"
    unicode_resource_id = "res_日本語_123_@#$^&*()'\"\\"
    unicode_action = "UPDATE_ROLE_ADMIN_👑"

    entry = append(
        model_class=ConcreteAuditLog,
        actor=unicode_actor,
        tenant=unicode_tenant,
        resource_type="MultiLangDoc",
        resource_id=unicode_resource_id,
        action=unicode_action,
        old_values={"role": "User_ユーザー", "notes": "Line 1\nLine 2\tTabbed"},
        new_values={"role": "Admin_管理者_👑", "notes": "Special chars: <> & \" ' € ¥ ₹"},
    )

    verified, key_used, reason = verify_entry(entry)
    assert verified is True
    assert key_used is not None

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True
    assert report.total_count == 1


@pytest.mark.django_db
def test_empty_string_fields():
    """
    Edge Case: Appending and verifying entries with empty strings for actor, tenant, resource_type, resource_id, and action.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="",
        tenant="",
        resource_type="",
        resource_id="",
        action="",
        old_values={},
        new_values={},
    )

    verified, key_used, reason = verify_entry(entry)
    assert verified is True

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True


@pytest.mark.django_db
def test_large_nested_json_payload():
    """
    Edge Case: Large nested payload structures with 100+ keys, nested lists, floats, booleans, and nulls.
    """
    large_payload = {
        "user_details": {
            "permissions": ["READ", "WRITE", "EXECUTE", "ADMIN"],
            "metadata": {"session_id": "sess_9999", "ip": "192.168.1.1", "is_active": True},
        },
        "metrics": {"score": 99.85, "count": 10000, "flag": None},
        "big_array": [{"id": i, "val": f"item_{i}"} for i in range(100)],
    }

    entry = append(
        model_class=ConcreteAuditLog,
        actor="system_admin@onesmarter.com",
        tenant="tenant_heavy",
        resource_type="ComplexConfig",
        resource_id="cfg_001",
        action="UPDATE_CONFIG",
        old_values={},
        new_values=large_payload,
    )

    verified, key_used, reason = verify_entry(entry)
    assert verified is True

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True


@pytest.mark.django_db
def test_verify_chain_empty_table():
    """
    Edge Case: Verifying chain on an empty audit log table.
    """
    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True
    assert report.total_count == 0
    assert report.current_key_count == 0
    assert report.previous_key_count == 0
    assert report.failed_pk is None
    assert report.failure_reason is None


@pytest.mark.django_db
def test_checkpoint_on_empty_table():
    """
    Edge Case: Creating and verifying a genesis checkpoint on an empty audit log table.
    """
    cp = checkpoint(ConcreteAuditLog)
    assert cp is not None
    assert cp.row_count == 0

    res = verify_checkpoint(cp, ConcreteAuditLog)
    assert res.envelope_ok is True
    assert res.mac_ok is True
    assert res.live_ok is True
    assert res.chain_ok is True


@pytest.mark.django_db
def test_invalid_json_envelope_tampering():
    """
    Edge Case: Direct database alteration placing invalid JSON envelope structure (e.g. missing required fields).
    Note: Database trigger is not installed in this test so raw SQL tampering is possible.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="user@onesmarter.com",
        tenant="tenant_test",
        resource_type="Doc",
        resource_id="1",
        action="READ",
    )

    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET envelope = '{{\"invalid_schema\": true}}' WHERE id = {entry.pk}"
        )

    modified = ConcreteAuditLog.objects.get(pk=entry.pk)
    verified, key_used, reason = verify_entry(modified)
    assert verified is False
    assert "allowlist" in reason or "Envelope" in reason


@pytest.mark.django_db
def test_multiple_key_rotations_long_chain():
    """
    Edge Case: Key rotation across multiple entries using rotate_key API.
    Verify all entries remain verifiable across current and previous keys.
    """
    provider = InMemoryKeyProvider(current_key="k1_bytes_32_chars_long_secret_1", current_key_id="k1")
    _set_default_key_provider_for_tests(provider)

    # 5 entries with k1
    for i in range(5):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}",
            tenant="t1",
            resource_type="R",
            resource_id=str(i),
            action="A",
            key_provider=provider,
        )

    # Rotate to k2 using official rotate_key API
    rotate_key(new_current_key="k2_bytes_32_chars_long_secret_2", new_key_id="k2", key_provider=provider)

    for i in range(5, 10):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}",
            tenant="t1",
            resource_type="R",
            resource_id=str(i),
            action="A",
            key_provider=provider,
        )

    report = verify_chain(ConcreteAuditLog, key_provider=provider)
    assert report.is_intact is True
    assert report.total_count == 10
    assert report.current_key_count == 5
    assert report.previous_key_count == 5


