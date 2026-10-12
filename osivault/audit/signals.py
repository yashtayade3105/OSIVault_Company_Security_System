# ==============================================================================
# OSIVault In-Built Signal & Context Auditing Helpers (Date: 24-09-2026)
# Allows 1-line automatic signal auditing registration for any Django model,
# supporting CREATE, UPDATE (with pre-save diff tracking), and DELETE.
# ==============================================================================

import math
import threading
from typing import Type, Optional, List, Dict, Any
from django.db.models.signals import pre_save, post_save, post_delete
from django.dispatch import receiver
from osivault.audit.models import OSIVaultAuditLog
from osivault.audit.operations import append

# Thread-Local storage for automatic request-level actor & tenant context
_thread_locals = threading.local()


def set_current_actor(actor: str):
    """Sets the current request/execution actor in thread-local storage."""
    _thread_locals.current_actor = str(actor)


def get_current_actor() -> Optional[str]:
    """Retrieves the current request/execution actor from thread-local storage."""
    return getattr(_thread_locals, "current_actor", None)


def clear_current_actor():
    """Clears thread-local actor storage."""
    if hasattr(_thread_locals, "current_actor"):
        del _thread_locals.current_actor


def set_current_tenant(tenant: str):
    """Sets the current request/execution tenant in thread-local storage."""
    _thread_locals.current_tenant = str(tenant)


def get_current_tenant() -> Optional[str]:
    """Retrieves the current request/execution tenant from thread-local storage."""
    return getattr(_thread_locals, "current_tenant", None)


def clear_current_tenant():
    """Clears thread-local tenant storage."""
    if hasattr(_thread_locals, "current_tenant"):
        del _thread_locals.current_tenant


def serialize_model_instance(instance) -> dict:
    """Utility to convert any Django model fields to a JSON-serializable dict."""
    if instance is None:
        return {}
    data = {}
    for field in instance._meta.fields:
        try:
            val = getattr(instance, field.name)
            if hasattr(val, "pk"):
                val = val.pk
            if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                val = None
            elif hasattr(val, "isoformat"):
                val = val.isoformat()
            elif not isinstance(val, (int, float, str, bool, type(None), dict, list)):
                val = str(val)
            data[field.name] = val
        except Exception:
            data[field.name] = None
    return data


def resolve_actor(instance, actor_field: Optional[str] = None) -> str:
    """
    Resolves actor in priority order:
    1. Model instance attribute specified by actor_field
    2. Thread-local current_actor (set by middleware or set_current_actor)
    3. Model instance 'actor' or 'user' or 'created_by' attribute
    4. Fallback to 'system'
    """
    if actor_field and hasattr(instance, actor_field):
        val = getattr(instance, actor_field)
        if val:
            return str(val)

    tl_actor = get_current_actor()
    if tl_actor:
        return str(tl_actor)

    for attr in ["actor", "created_by", "modified_by", "user"]:
        if hasattr(instance, attr):
            val = getattr(instance, attr)
            if val:
                return str(val)

    return "system"


def resolve_tenant(tenant_name: str) -> str:
    """
    Resolves tenant in priority order:
    1. Thread-local current_tenant
    2. Explicit tenant_name passed to registration
    3. Default to "default_tenant"
    """
    tl_tenant = get_current_tenant()
    if tl_tenant:
        return str(tl_tenant)
    return tenant_name or "default_tenant"


def register_audit_signal(
    target_model_class,
    audit_model_class: Type[OSIVaultAuditLog],
    central_audit_model_class: Optional[Type[OSIVaultAuditLog]] = None,
    tenant_name: str = "default_tenant",
    actor_field: Optional[str] = None
):
    """
    In-Built OSIVault Helper to register 1-line automatic signals for any Django model.
    Handles CREATE, UPDATE (with pre-save diff snapshotting), and DELETE.
    Automatically installs PostgreSQL immutability triggers on audit log tables.
    Usage:
        register_audit_signal(Student, StudentAuditLog, CollegeMasterAuditLog)
    """

    # 0. Auto-install PostgreSQL BEFORE UPDATE OR DELETE triggers on audit tables safely without app initialization warning
    def _safe_install_triggers():
        try:
            from osivault.audit.postgres import install_postgres_immutability_trigger
            if audit_model_class and hasattr(audit_model_class, "_meta"):
                install_postgres_immutability_trigger(audit_model_class._meta.db_table)
            if central_audit_model_class and hasattr(central_audit_model_class, "_meta"):
                install_postgres_immutability_trigger(central_audit_model_class._meta.db_table)
        except Exception:
            pass

    try:
        from django.apps import apps
        if apps.ready:
            _safe_install_triggers()
        else:
            from django.db.models.signals import post_migrate
            @receiver(post_migrate)
            def _on_post_migrate_install_triggers(sender, **kwargs):
                _safe_install_triggers()
    except Exception:
        _safe_install_triggers()

    # 1. Pre-Save Handler: Snapshot previous values for UPDATE diff tracking
    @receiver(pre_save, sender=target_model_class, weak=False)
    def auto_audit_pre_save_handler(sender, instance, **kwargs):
        if instance.pk:
            try:
                old_instance = sender.objects.filter(pk=instance.pk).first()
                if old_instance:
                    instance._osivault_old_snapshot = serialize_model_instance(old_instance)
            except Exception:
                instance._osivault_old_snapshot = {}

    # 2. Post-Save Handler: Process CREATE and UPDATE events
    @receiver(post_save, sender=target_model_class, weak=False)
    def auto_audit_post_save_handler(sender, instance, created, **kwargs):
        action = f"CREATE_{sender.__name__.upper()}" if created else f"UPDATE_{sender.__name__.upper()}"
        new_vals = serialize_model_instance(instance)
        
        if created:
            old_vals = {}
        else:
            old_vals = getattr(instance, "_osivault_old_snapshot", {})
            if hasattr(instance, "_osivault_old_snapshot"):
                delattr(instance, "_osivault_old_snapshot")

        actor = resolve_actor(instance, actor_field=actor_field)
        tenant = resolve_tenant(tenant_name)
        res_id = str(getattr(instance, "pk", "") or "unknown")

        # Append to Dedicated Audit Model
        append(
            model_class=audit_model_class,
            actor=actor,
            tenant=tenant,
            resource_type=sender.__name__,
            resource_id=res_id,
            action=action,
            old_values=old_vals,
            new_values=new_vals
        )

        # Append to Central Audit Model if specified
        if central_audit_model_class and central_audit_model_class != audit_model_class:
            append(
                model_class=central_audit_model_class,
                actor=actor,
                tenant=tenant,
                resource_type=sender.__name__,
                resource_id=res_id,
                action=action,
                old_values=old_vals,
                new_values=new_vals
            )

    # 3. Post-Delete Handler: Process DELETE events
    @receiver(post_delete, sender=target_model_class, weak=False)
    def auto_audit_post_delete_handler(sender, instance, **kwargs):
        action = f"DELETE_{sender.__name__.upper()}"
        old_vals = serialize_model_instance(instance)
        new_vals = {}

        actor = resolve_actor(instance, actor_field=actor_field)
        tenant = resolve_tenant(tenant_name)
        res_id = str(getattr(instance, "pk", "") or "unknown")

        # Append to Dedicated Audit Model
        append(
            model_class=audit_model_class,
            actor=actor,
            tenant=tenant,
            resource_type=sender.__name__,
            resource_id=res_id,
            action=action,
            old_values=old_vals,
            new_values=new_vals
        )

        # Append to Central Audit Model if specified
        if central_audit_model_class and central_audit_model_class != audit_model_class:
            append(
                model_class=central_audit_model_class,
                actor=actor,
                tenant=tenant,
                resource_type=sender.__name__,
                resource_id=res_id,
                action=action,
                old_values=old_vals,
                new_values=new_vals
            )

    return (auto_audit_pre_save_handler, auto_audit_post_save_handler, auto_audit_post_delete_handler)


def audit_bulk_delete(
    queryset,
    audit_model_class: Type[OSIVaultAuditLog],
    central_audit_model_class: Optional[Type[OSIVaultAuditLog]] = None,
    tenant_name: str = "default_tenant",
    actor: Optional[str] = None
) -> int:
    """
    Modular Helper to safely delete a QuerySet while recording HMAC chained audit logs for every deleted instance.
    Usage:
        count = audit_bulk_delete(Student.objects.filter(is_active=False), StudentAuditLog, CollegeMasterAuditLog)
    """
    instances = list(queryset)
    if not instances:
        return 0

    resolved_actor = actor or get_current_actor() or "system"
    resolved_tenant = get_current_tenant() or tenant_name or "default_tenant"

    for instance in instances:
        action = f"DELETE_{instance.__class__.__name__.upper()}"
        old_vals = serialize_model_instance(instance)
        res_id = str(getattr(instance, "pk", "") or "unknown")

        append(
            model_class=audit_model_class,
            actor=resolved_actor,
            tenant=resolved_tenant,
            resource_type=instance.__class__.__name__,
            resource_id=res_id,
            action=action,
            old_values=old_vals,
            new_values={}
        )

        if central_audit_model_class and central_audit_model_class != audit_model_class:
            append(
                model_class=central_audit_model_class,
                actor=resolved_actor,
                tenant=resolved_tenant,
                resource_type=instance.__class__.__name__,
                resource_id=res_id,
                action=action,
                old_values=old_vals,
                new_values={}
            )

    # Perform actual queryset deletion
    count, _ = queryset.delete()
    return count


class OSIVaultAuditMiddleware:
    """
    Django Middleware to automatically set current request actor & tenant in thread-local storage.
    Usage in settings.py:
        MIDDLEWARE = [
            ...
            'osivault.audit.signals.OSIVaultAuditMiddleware',
        ]
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            actor_name = getattr(user, "username", None) or getattr(user, "email", None) or str(user)
            set_current_actor(actor_name)
        else:
            set_current_actor("anonymous_user")

        # Set tenant from HTTP header if present
        tenant_hdr = request.headers.get("X-Tenant-ID") or request.headers.get("X-Tenant")
        if tenant_hdr:
            set_current_tenant(tenant_hdr)

        try:
            response = self.get_response(request)
            return response
        finally:
            clear_current_actor()
            clear_current_tenant()
