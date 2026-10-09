from django.apps import AppConfig


class EDIVaultConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "edi_vault"
    verbose_name = "EDI Vault & Processing Core"

    def ready(self):
        try:
            from edi_vault.models import (
                EDIDocument, 
                EDIMemberRecord, 
                EDIDocumentAuditLog, 
                EDIMemberAuditLog, 
                SaaSCompanyCentralAuditLog
            )
            from osivault.audit import register_audit_signal

            # Register 1-line automatic signals for CREATE, UPDATE (with pre-save diff snapshotting), and DELETE
            register_audit_signal(
                target_model_class=EDIDocument,
                audit_model_class=EDIDocumentAuditLog,
                central_audit_model_class=SaaSCompanyCentralAuditLog,
                tenant_name="onesmarter_saas"
            )

            register_audit_signal(
                target_model_class=EDIMemberRecord,
                audit_model_class=EDIMemberAuditLog,
                central_audit_model_class=SaaSCompanyCentralAuditLog,
                tenant_name="onesmarter_saas"
            )
        except Exception as e:
            pass
