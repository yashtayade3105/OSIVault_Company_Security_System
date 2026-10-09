import hashlib
from django.db import models
from django.utils.timezone import now


class EDIDocument(models.Model):
    """
    SaaS Model representing an uploaded EDI Document (ANSI X12 834/835/270).
    """
    STATUS_CHOICES = [
        ("UPLOADED", "Uploaded"),
        ("PARSED", "Parsed & Synced to DB"),
        ("STORED_ENCRYPTED", "Stored Encrypted in Directory"),
        ("FAILED", "Processing Failed"),
    ]

    file_name = models.CharField(max_length=255)
    file_type = models.CharField(max_length=100, default="834_BENEFIT_ENROLLMENT")
    interchange_control_number = models.CharField(max_length=100, blank=True, null=True)
    sender_id = models.CharField(max_length=100, blank=True, null=True)
    receiver_id = models.CharField(max_length=100, blank=True, null=True)
    sponsor_name = models.CharField(max_length=255, blank=True, null=True)
    insurer_name = models.CharField(max_length=255, blank=True, null=True)
    
    file_size = models.IntegerField(default=0)
    sha256_checksum = models.CharField(max_length=64)
    server_storage_path = models.CharField(max_length=1024, blank=True, null=True)
    is_encrypted_on_disk = models.BooleanField(default=False)
    
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default="UPLOADED")
    total_records_parsed = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=now)

    class Meta:
        verbose_name = "EDI Document"
        verbose_name_plural = "EDI Documents"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.file_name} ({self.file_type} - {self.total_records_parsed} records)"


from osivault.fields import EncryptedCharField, EncryptedTextField, EncryptedJSONField, SearchHash

class EDIMemberRecord(models.Model):
    """
    Parsed Individual Member/Subscriber Record extracted from EDI 834 segments.
    PII fields (policy_number, address, city, dob) are protected at-rest using osivault.fields EncryptedCharField.
    Includes policy_number_bhash (HMAC-SHA256 blind index) for O(1) query search over encrypted data.
    """
    document = models.ForeignKey(EDIDocument, on_delete=models.CASCADE, related_name="members")
    member_id = models.CharField(max_length=100)
    policy_number = EncryptedCharField(max_length=512, blank=True, null=True)
    policy_number_bhash = models.CharField(max_length=64, db_index=True, blank=True, null=True)
    
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    dob = EncryptedCharField(max_length=512, blank=True, null=True)
    gender = models.CharField(max_length=10, blank=True, null=True)
    
    address = EncryptedCharField(max_length=512, blank=True, null=True)
    city = EncryptedCharField(max_length=512, blank=True, null=True)
    state = models.CharField(max_length=50, blank=True, null=True)
    zip_code = models.CharField(max_length=20, blank=True, null=True)
    
    coverage_plan = models.CharField(max_length=100, blank=True, null=True)
    relationship_code = models.CharField(max_length=50, blank=True, null=True)
    
    # Encrypted JSON Payload Field
    metadata_json = EncryptedJSONField(blank=True, null=True)

    class Meta:
        verbose_name = "EDI Member Record"
        verbose_name_plural = "EDI Member Records"

    @property
    def full_name(self):
        return f"{self.first_name or ''} {self.last_name or ''}".strip() or self.member_id

    def __str__(self):
        return f"{self.full_name} ({self.member_id})"


class EDIAuditEvent(models.Model):
    """
    Audit Log Event tracking file lifecycle (Upload, Parser, Encryption, Directory storage).
    """
    document = models.ForeignKey(EDIDocument, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_events")
    action = models.CharField(max_length=100)
    details = models.TextField()
    sha256_hash = models.CharField(max_length=64, blank=True, null=True)
    timestamp = models.DateTimeField(default=now)

    class Meta:
        verbose_name = "EDI Audit Event"
        verbose_name_plural = "EDI Audit Events"
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S')}] {self.action} - {self.details[:50]}"


# ==============================================================================
# osivault.audit: Tamper-Evident Immutable Audit Log Models
# ==============================================================================
from osivault.audit.models import OSIVaultAuditLog


class EDIDocumentAuditLog(OSIVaultAuditLog):
    """
    Dedicated tamper-evident, keyed & chained audit log for EDI Documents.
    Subclasses OSIVaultAuditLog to inherit ORM immutability guards & SHA-256 chain validation.
    """
    class Meta:
        db_table = "edi_document_audit_log"
        verbose_name = "EDI Document Audit Log"
        verbose_name_plural = "EDI Document Audit Logs"


class EDIMemberAuditLog(OSIVaultAuditLog):
    """
    Dedicated tamper-evident, keyed & chained audit log for EDI Member Records.
    Subclasses OSIVaultAuditLog to inherit ORM immutability guards & SHA-256 chain validation.
    """
    class Meta:
        db_table = "edi_member_audit_log"
        verbose_name = "EDI Member Audit Log"
        verbose_name_plural = "EDI Member Audit Logs"


class SaaSCompanyCentralAuditLog(OSIVaultAuditLog):
    """
    Centralized tamper-evident audit log across all SaaS application models.
    """
    class Meta:
        db_table = "saas_company_central_audit_log"
        verbose_name = "SaaS Central Audit Log"
        verbose_name_plural = "SaaS Central Audit Logs"
