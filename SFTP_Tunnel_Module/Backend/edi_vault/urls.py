from django.urls import path
from edi_vault import views

urlpatterns = [
    # Core SaaS EDI Endpoints
    path("documents/upload/", views.upload_edi_file_api, name="upload_edi_file"),
    path("documents/", views.list_documents_api, name="list_documents"),
    path("documents/<int:pk>/", views.get_document_details_api, name="get_document_details"),
    path("members/", views.list_members_api, name="list_members"),
    path("audit/", views.list_audit_events_api, name="list_audit_events"),
    path("dashboard/stats/", views.get_dashboard_analytics_api, name="get_dashboard_analytics"),
    path("server-directory/files/", views.list_server_directory_files_api, name="list_server_directory_files"),

    # OSIVault Security System Integration Endpoints
    path("osivault/sftp/superusers/", views.list_osivault_sftp_superusers_api, name="osivault_sftp_superusers"),
    path("osivault/sftp/logs/", views.list_osivault_sftp_logs_api, name="osivault_sftp_logs"),
    path("osivault/sftp/encrypt-file/", views.encrypt_server_directory_file_api, name="osivault_sftp_encrypt_file"),
    path("osivault/sftp/decrypt-file/", views.decrypt_server_directory_file_api, name="osivault_sftp_decrypt_file"),
    
    # osivault.fields Endpoints
    path("osivault/fields/inspect/", views.inspect_osivault_fields_api, name="osivault_fields_inspect"),
    path("osivault/fields/search/", views.search_osivault_fields_blind_index_api, name="osivault_fields_search"),
    path("osivault/fields/rotate-keys/", views.rotate_osivault_fields_keys_api, name="osivault_fields_rotate_keys"),

    # osivault.audit Specific Cryptographic Verification Endpoints
    path("osivault/audit/logs/", views.list_osivault_audit_logs_api, name="osivault_audit_logs"),
    path("osivault/audit/verify-chain/", views.verify_osivault_audit_chain_api, name="osivault_audit_verify_chain"),
    path("osivault/audit/checkpoint/", views.create_osivault_audit_checkpoint_api, name="osivault_audit_checkpoint"),

    # osivault.auth Inspection Endpoint
    path("osivault/auth/inspect/", views.inspect_osivault_auth_api, name="osivault_auth_inspect"),
]
