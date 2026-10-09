"""
osivault.auth.urls: Plug-and-play URL patterns for OSIVault Auth Module built-in views and APIs.
"""

from django.urls import path
from osivault.auth import views

app_name = "osivault_auth"

urlpatterns = [
    path("portal/", views.user_portal_view, name="user-portal"),
    path("setup/", views.mfa_setup_view, name="mfa-setup"),
    path("admin-login/", views.admin_login_view, name="admin-login"),
    
    # Email OTP & User Authentication APIs
    path("api/email-otp/send/", views.send_email_otp_api, name="api-send-email-otp"),
    path("api/email-otp/verify/", views.verify_email_otp_api, name="api-verify-email-otp"),
    path("api/user/register/", views.register_user_api, name="api-register-user"),
    path("api/user/login/", views.login_user_api, name="api-login-user"),
    path("api/user/logout/", views.logout_user_api, name="api-logout-user"),
    path("api/user/mfa-status/", views.user_mfa_status_api, name="api-user-mfa-status"),
    path("api/totp/setup/", views.totp_setup_api, name="api-totp-setup"),
    path("api/totp/verify/", views.totp_verify_api, name="api-totp-verify"),

    # Emergency Break-Glass Recovery Codes APIs
    path("api/recovery-codes/generate/", views.generate_recovery_codes_api, name="api-recovery-codes-generate"),
    path("api/recovery-codes/verify/", views.verify_recovery_code_api, name="api-recovery-codes-verify"),

    # WebAuthn YubiKey Hardware APIs (2-Key Slot Support)
    path("api/webauthn/keys/list/", views.list_webauthn_keys_api, name="api-webauthn-keys-list"),
    path("api/webauthn/register/options/", views.webauthn_register_options_api, name="api-webauthn-register-options"),
    path("api/webauthn/register/verify/", views.webauthn_register_verify_api, name="api-webauthn-register-verify"),
    path("api/webauthn/assertion/options/", views.webauthn_assertion_options_api, name="api-webauthn-assertion-options"),
    path("api/webauthn/assertion/verify/", views.webauthn_assertion_verify_api, name="api-webauthn-assertion-verify"),
    path("api/webauthn/keys/revoke/", views.revoke_webauthn_key_api, name="api-webauthn-keys-revoke"),
]
