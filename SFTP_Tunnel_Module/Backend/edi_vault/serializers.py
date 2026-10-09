from rest_framework import serializers
from edi_vault.models import EDIDocument, EDIMemberRecord, EDIAuditEvent


class EDIMemberRecordSerializer(serializers.ModelSerializer):
    full_name = serializers.ReadOnlyField()

    class Meta:
        model = EDIMemberRecord
        fields = "__all__"


class EDIAuditEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = EDIAuditEvent
        fields = "__all__"


class EDIDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = EDIDocument
        fields = "__all__"


class EDIDocumentDetailSerializer(serializers.ModelSerializer):
    members = EDIMemberRecordSerializer(many=True, read_only=True)
    audit_events = EDIAuditEventSerializer(many=True, read_only=True)

    class Meta:
        model = EDIDocument
        fields = "__all__"
