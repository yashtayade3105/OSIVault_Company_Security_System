"""
PostgreSQL immutability trigger installation helper for consuming applications.
"""

from django.db import connection


def install_postgres_immutability_trigger(table_name: str) -> None:
    """
    Installs a PostgreSQL BEFORE UPDATE OR DELETE trigger raising an exception.
    Permits no carve-outs.
    """
    if not table_name:
        return

    if "postgres" not in connection.vendor.lower():
        return

    trigger_function = f"osivault_prevent_immutability_{table_name}"
    trigger_name = f"trg_osivault_immutable_{table_name}"

    sql = f"""
    CREATE OR REPLACE FUNCTION {trigger_function}()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'OSIVault audit entries are immutable and cannot be updated or deleted from table %', TG_TABLE_NAME;
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS {trigger_name} ON "{table_name}";

    CREATE TRIGGER {trigger_name}
    BEFORE UPDATE OR DELETE ON "{table_name}"
    FOR EACH ROW EXECUTE FUNCTION {trigger_function}();
    """

    try:
        with connection.cursor() as cursor:
            cursor.execute(sql)
    except Exception as e:
        print(f"[OSIVault Audit Warn] Could not install PostgreSQL trigger on '{table_name}': {e}")


def install_postgres_immutability_triggers(*table_names: str) -> None:
    """
    Installs PostgreSQL BEFORE UPDATE OR DELETE triggers on multiple tables in sequence.
    """
    for table_name in table_names:
        install_postgres_immutability_trigger(table_name)


def install_all_osivault_audit_triggers() -> list:
    """
    Auto-discovers all concrete subclasses of OSIVaultAuditLog and installs PostgreSQL immutability triggers.
    """
    from osivault.audit.models import OSIVaultAuditLog
    installed = []
    for cls in OSIVaultAuditLog.__subclasses__():
        if getattr(cls._meta, "abstract", False):
            continue
        tbl = cls._meta.db_table
        if tbl:
            install_postgres_immutability_trigger(tbl)
            installed.append(tbl)
    return installed

