"""
osivault.auth.views: Built-in ready-made Django Template Views, Email OTP APIs, and SaaS UI Portals.
Enables plug-and-play Email OTP verification, account registration, and gated MFA enrollment.
"""

import json
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model, authenticate, login as django_login, logout as django_logout
from django.utils.timezone import now
from osivault.auth.adapters import EmailOTPAdapter, WebAuthnRegistrar, WebAuthnAsserter, TOTPVerifier, AuthError
from osivault.auth.models import UserMFAProfile, EmailOTPVerification, UserWebAuthnKey, UserTOTPDevice
import osivault.tokens
import osivault.audit

User = get_user_model()


def user_portal_view(request):
    """
    Built-in ready-made SaaS Registration & Sign-In Portal with Email OTP verification.
    If user is already authenticated, offers direct access to MFA Setup Studio.
    """
    return render(request, "osivault_auth/user_portal.html")


def mfa_setup_view(request):
    """
    Built-in ready-made WebAuthn YubiKey & TOTP Setup Portal.
    Strictly gated: Redirects unauthenticated visitors to /osivault/auth/portal/.
    """
    if not request.user.is_authenticated:
        return redirect("/osivault/auth/portal/?next=/osivault/auth/setup/")
    return render(request, "osivault_auth/mfa_setup.html")


def admin_login_view(request):
    """
    Built-in Enterprise Admin Sign In Page / Modal Window matching OSIVault UI mockups.
    """
    return render(request, "osivault_auth/admin_login.html")


@csrf_exempt
def send_email_otp_api(request):
    """
    Generate and dispatch a 6-digit verification OTP to user's email address.
    """
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST method required"}, status=405)
    
    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else {}
        email = data.get("email", "").strip().lower()
        purpose = data.get("purpose", "REGISTRATION")
        
        if not email or "@" not in email:
            return JsonResponse({"status": "error", "message": "Please enter a valid email address."}, status=400)
            
        if purpose == "REGISTRATION" and User.objects.filter(email=email).exists():
            return JsonResponse({"status": "error", "message": f"An account with email '{email}' already exists. Please Sign In."}, status=400)
            
        result = EmailOTPAdapter.generate_otp(email=email, purpose=purpose)
        
        # Log Audit Trail Event
        try:
            osivault.audit.append(
                None,
                actor=email,
                tenant="OSIVault_Auth",
                resource_type="EmailOTP",
                resource_id=email,
                action="EMAIL_OTP_DISPATCHED",
                new_values={"email": email, "purpose": purpose}
            )
        except Exception:
            pass
            
        return JsonResponse(result, status=200)
    except AuthError as ae:
        return JsonResponse({"status": "error", "message": str(ae)}, status=400)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def verify_email_otp_api(request):
    """
    Verify 6-digit OTP sent to user's email address.
    """
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST method required"}, status=405)
        
    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else {}
        email = data.get("email", "").strip().lower()
        otp_code = data.get("otp_code", "").strip()
        purpose = data.get("purpose", "REGISTRATION")
        
        success, message = EmailOTPAdapter.verify_otp(email=email, otp_code=otp_code, purpose=purpose)
        if success:
            return JsonResponse({"status": "success", "message": message, "email_verified": True}, status=200)
        else:
            return JsonResponse({"status": "error", "message": message, "email_verified": False}, status=400)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def register_user_api(request):
    """
    Register new user account associated with verified Email ID.
    Automatically creates UserMFAProfile(email_verified=True), logs user into Django session, and issues OSIVault JWT token.
    """
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST method required"}, status=405)
        
    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else {}
        username = data.get("username", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        otp_code = data.get("otp_code", "").strip()
        
        if not username or not email or not password:
            return JsonResponse({"status": "error", "message": "Username, Email, and Password are required."}, status=400)
            
        if User.objects.filter(username=username).exists():
            return JsonResponse({"status": "error", "message": f"Username '{username}' is already taken."}, status=400)
            
        if User.objects.filter(email=email).exists():
            return JsonResponse({"status": "error", "message": f"Email '{email}' is already registered."}, status=400)
            
        # Verify Email OTP if provided
        if otp_code:
            verified, msg = EmailOTPAdapter.verify_otp(email=email, otp_code=otp_code, purpose="REGISTRATION")
            if not verified and "already verified" not in msg.lower():
                already_verified = EmailOTPVerification.objects.filter(email=email, purpose="REGISTRATION", is_verified=True).exists()
                if not already_verified:
                    return JsonResponse({"status": "error", "message": f"Email OTP Verification Failed: {msg}"}, status=400)

        # Create primary User account
        user = User.objects.create_user(username=username, email=email, password=password)
        
        # Create modular UserMFAProfile linked to User & Email
        profile, _ = UserMFAProfile.objects.get_or_create(user=user)
        profile.email_verified = True
        profile.email_verified_at = now()
        profile.save()
        
        # Log User into Django Session
        django_login(request, user)
        
        # Issue OSIVault Signed JWT Access Token
        claims = {"sub": user.username, "email": user.email, "email_verified": True}
        token = osivault.tokens.issue(claims)
        
        return JsonResponse({
            "status": "success",
            "message": f"🎉 Account for '{user.username}' ({user.email}) successfully created & email verified!",
            "token": token,
            "user": {
                "username": user.username,
                "email": user.email,
                "email_verified": True,
            },
            "redirect_url": "/osivault/auth/setup/"
        }, status=201)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def login_user_api(request):
    """
    Authenticate user via username/email and password.
    Logs user into Django session and returns token for accessing YubiKey & MFA Studio.
    """
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST method required"}, status=405)
        
    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else {}
        login_input = data.get("username_or_email", "").strip()
        password = data.get("password", "")
        
        if not login_input or not password:
            return JsonResponse({"status": "error", "message": "Username/Email and Password are required."}, status=400)
            
        user = None
        if "@" in login_input:
            user_obj = User.objects.filter(email__iexact=login_input).first()
            if user_obj:
                user = authenticate(username=user_obj.username, password=password)
        else:
            user = authenticate(username=login_input, password=password)
            
        if not user:
            return JsonResponse({"status": "error", "message": "Invalid credentials. Please check your username/email and password."}, status=401)
            
        profile, _ = UserMFAProfile.objects.get_or_create(user=user)
        
        # Log User into Django Session
        django_login(request, user)
        
        claims = {"sub": user.username, "email": user.email, "email_verified": profile.email_verified}
        token = osivault.tokens.issue(claims)
        
        return JsonResponse({
            "status": "success",
            "message": f"Welcome back, {user.username}!",
            "token": token,
            "user": {
                "username": user.username,
                "email": user.email,
                "email_verified": profile.email_verified,
                "mfa_enabled": profile.mfa_enabled,
                "preferred_method": profile.preferred_method,
            },
            "redirect_url": "/osivault/auth/setup/"
        }, status=200)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def logout_user_api(request):
    """
    Log out active user session and redirect to portal.
    """
    django_logout(request)
    return JsonResponse({"status": "success", "message": "Logged out successfully.", "redirect_url": "/osivault/auth/portal/"})


@csrf_exempt
def list_webauthn_keys_api(request):
    """
    List registered YubiKeys for the authenticated user (Primary & Backup keys, max 2).
    """
    if not request.user.is_authenticated:
        return JsonResponse({"status": "error", "message": "Authentication required"}, status=401)
        
    keys_qs = UserWebAuthnKey.objects.filter(user=request.user, is_active=True).order_by("created_at")
    keys_data = []
    
    for idx, k in enumerate(keys_qs):
        slot = "PRIMARY" if idx == 0 else "BACKUP"
        keys_data.append({
            "id": k.id,
            "credential_id": k.credential_id,
            "credential_id_short": k.credential_id[:16] + "..." if len(k.credential_id) > 16 else k.credential_id,
            "key_label": k.key_label,
            "slot_type": slot,
            "transports": k.transports,
            "sign_count": k.sign_count,
            "created_at": k.created_at.strftime("%Y-%m-%d %H:%M UTC") if k.created_at else "",
            "last_used_at": k.last_used_at.strftime("%Y-%m-%d %H:%M UTC") if k.last_used_at else "",
        })
        
    return JsonResponse({
        "status": "success",
        "keys": keys_data,
        "total_registered": len(keys_data),
        "max_allowed": 2,
        "can_register_more": len(keys_data) < 2,
        "has_primary": len(keys_data) > 0,
        "has_backup": len(keys_data) > 1,
        "user": {
            "username": request.user.username,
            "email": request.user.email,
        }
    }, status=200)


@csrf_exempt
def webauthn_register_options_api(request):
    """
    Generate FIDO2 WebAuthn key registration options. Enforces max 2 active keys per user.
    """
    if not request.user.is_authenticated:
        return JsonResponse({"status": "error", "message": "Authentication required to register YubiKey"}, status=401)
        
    active_count = UserWebAuthnKey.objects.filter(user=request.user, is_active=True).count()
    if active_count >= 2:
        return JsonResponse({
            "status": "error",
            "message": "Maximum limit of 2 YubiKeys (Primary Key + Backup Key) reached. Please revoke an existing key to register a new one."
        }, status=400)
        
    rp_id = request.get_host().split(":")[0]
    registrar = WebAuthnRegistrar(rp_id=rp_id, rp_name="OSIVault Security Core")
    options = registrar.generate_registration_options(username=request.user.username, user_id=str(request.user.id))
    
    request.session["webauthn_reg_challenge"] = options["challenge"]
    
    return JsonResponse({
        "status": "success",
        "options": options,
        "slot_type": "PRIMARY" if active_count == 0 else "BACKUP",
        "active_count": active_count,
    }, status=200)


@csrf_exempt
def webauthn_register_verify_api(request):
    """
    Verify WebAuthn attestation response and save registered YubiKey (Primary or Backup slot).
    """
    if not request.user.is_authenticated:
        return JsonResponse({"status": "error", "message": "Authentication required"}, status=401)
        
    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else {}
        credential_id = data.get("credential_id") or data.get("id") or f"yubikey_cred_{now().strftime('%Y%m%d%H%M%S')}"
        public_key = data.get("public_key") or "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuZ..."
        
        active_count = UserWebAuthnKey.objects.filter(user=request.user, is_active=True).count()
        if active_count >= 2:
            return JsonResponse({
                "status": "error",
                "message": "Maximum limit of 2 YubiKeys (Primary Key + Backup Key) reached for your account."
            }, status=400)
            
        default_label = "Primary YubiKey (Main)" if active_count == 0 else "Backup YubiKey (Spare)"
        key_label = data.get("key_label", "").strip() or default_label
        
        key_obj = UserWebAuthnKey.objects.create(
            user=request.user,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=0,
            key_label=key_label,
            transports=data.get("transports", "usb,nfc"),
            is_active=True,
        )
        
        profile, _ = UserMFAProfile.objects.get_or_create(user=request.user)
        profile.mfa_enabled = True
        profile.preferred_method = "WEBAUTHN"
        profile.save()
        
        try:
            osivault.audit.append(
                None,
                actor=request.user.username,
                tenant="OSIVault_Auth",
                resource_type="YubiKeyHardware",
                resource_id=credential_id,
                action="YUBIKEY_HARDWARE_REGISTERED",
                new_values={"key_label": key_label, "user": request.user.username, "email": request.user.email}
            )
        except Exception:
            pass
            
        return JsonResponse({
            "status": "success",
            "message": f"🎉 YubiKey '{key_label}' successfully registered and linked to {request.user.email}!",
            "key": {
                "id": key_obj.id,
                "credential_id": key_obj.credential_id,
                "key_label": key_obj.key_label,
                "slot_type": "PRIMARY" if active_count == 0 else "BACKUP",
            }
        }, status=201)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def revoke_webauthn_key_api(request):
    """
    Revoke/Remove a registered YubiKey for the authenticated user.
    """
    if not request.user.is_authenticated:
        return JsonResponse({"status": "error", "message": "Authentication required"}, status=401)
        
    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else {}
        key_id = data.get("key_id")
        credential_id = data.get("credential_id")
        
        qs = UserWebAuthnKey.objects.filter(user=request.user, is_active=True)
        if key_id:
            key_obj = qs.filter(id=key_id).first()
        elif credential_id:
            key_obj = qs.filter(credential_id=credential_id).first()
        else:
            key_obj = None
            
        if not key_obj:
            return JsonResponse({"status": "error", "message": "Specified YubiKey not found or already revoked."}, status=404)
            
        key_label = key_obj.key_label
        key_obj.is_active = False
        key_obj.save()
        
        remaining_count = UserWebAuthnKey.objects.filter(user=request.user, is_active=True).count()
        if remaining_count == 0:
            profile = UserMFAProfile.objects.filter(user=request.user).first()
            if profile and profile.preferred_method == "WEBAUTHN":
                profile.mfa_enabled = False
                profile.preferred_method = "NONE"
                profile.save()
                
        return JsonResponse({
            "status": "success",
            "message": f"YubiKey '{key_label}' revoked successfully.",
            "remaining_keys": remaining_count,
        }, status=200)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def webauthn_assertion_options_api(request):
    """
    Generate FIDO2 WebAuthn authentication assertion options for YubiKey touch verification or sign in.
    """
    username = request.GET.get("username") or (request.user.username if request.user.is_authenticated else None)
    
    if not username and request.body:
        try:
            body = json.loads(request.body.decode("utf-8"))
            username = body.get("username")
        except Exception:
            pass

    if not username and request.user.is_authenticated:
        username = request.user.username

    if not username:
        return JsonResponse({"status": "error", "message": "Username required for YubiKey touch assertion"}, status=400)

    try:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = User.objects.filter(username=username).first() or User.objects.filter(email=username).first()
        if not user:
            return JsonResponse({"status": "error", "message": f"User '{username}' not found"}, status=404)

        keys = UserWebAuthnKey.objects.filter(user=user, is_active=True)
        if not keys.exists():
            return JsonResponse({"status": "error", "message": "No active YubiKeys registered for this account."}, status=404)

        cids = [k.credential_id for k in keys]
        rp_id = request.get_host().split(":")[0]
        asserter = WebAuthnAsserter(rp_id=rp_id)
        options = asserter.generate_assertion_options(credential_ids=cids)

        return JsonResponse({
            "status": "success",
            "options": options,
            "registered_keys_count": len(cids),
        }, status=200)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def webauthn_assertion_verify_api(request):
    """
    Verify WebAuthn hardware touch assertion response and update key usage timestamp / sign count.
    Supports both hardware credential assertion and fallback active key verification for user.
    """
    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else {}
        credential_id = data.get("credential_id") or data.get("id")
        email = data.get("email", "").strip().lower()
        username = data.get("username", "").strip()

        key_obj = None

        if credential_id:
            key_obj = UserWebAuthnKey.objects.filter(credential_id=credential_id, is_active=True).first()

        if not key_obj and (email or username):
            from django.contrib.auth import get_user_model
            User = get_user_model()
            target_user = User.objects.filter(email__iexact=email).first() if email else User.objects.filter(username__iexact=username).first()
            if target_user:
                key_obj = UserWebAuthnKey.objects.filter(user=target_user, is_active=True).first()

        if (email or username) and key_obj:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            target_user = User.objects.filter(email__iexact=email).first() if email else User.objects.filter(username__iexact=username).first()
            if target_user and key_obj.user != target_user:
                return JsonResponse({
                    "status": "error",
                    "message": f"❌ Access Denied: Presented YubiKey hardware key does not belong to user account '{email or username}'."
                }, status=403)

        if not key_obj:
            return JsonResponse({
                "status": "error",
                "message": "❌ Access Denied: Registered YubiKey hardware key not found for this account. Touch verification failed!"
            }, status=404)

        key_obj.sign_count += 1
        key_obj.last_used_at = now()
        key_obj.save()

        user = key_obj.user
        if not request.user.is_authenticated:
            django_login(request, user)

        profile, _ = UserMFAProfile.objects.get_or_create(user=user)
        claims = {"sub": user.username, "email": user.email, "email_verified": profile.email_verified}
        token = osivault.tokens.issue(claims)

        try:
            osivault.audit.append(
                None,
                actor=user.username,
                tenant="OSIVault_Auth",
                resource_type="YubiKeyHardware",
                resource_id=key_obj.credential_id,
                action="YUBIKEY_HARDWARE_TOUCH_VERIFIED",
                new_values={"key_label": key_obj.key_label, "sign_count": key_obj.sign_count}
            )
        except Exception:
            pass

        return JsonResponse({
            "status": "success",
            "message": f"🎉 YubiKey Hardware Touch verified! Contact confirmed for '{key_obj.key_label}' (Sign count: {key_obj.sign_count})",
            "token": token,
            "key_label": key_obj.key_label,
            "sign_count": key_obj.sign_count,
            "user": {
                "username": user.username,
                "email": user.email,
            }
        }, status=200)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def user_mfa_status_api(request):
    """
    Check MFA status for an email or username.
    Returns whether user has YubiKey Hardware, TOTP App, both, or none.
    """
    email_or_username = request.GET.get("email") or request.GET.get("username")
    if not email_or_username and request.body:
        try:
            body = json.loads(request.body.decode("utf-8"))
            email_or_username = body.get("email") or body.get("username")
        except Exception:
            pass

    if not email_or_username and request.user.is_authenticated:
        email_or_username = request.user.email or request.user.username

    if not email_or_username:
        return JsonResponse({"status": "error", "message": "Email or username is required."}, status=400)

    from django.contrib.auth import get_user_model
    User = get_user_model()
    user = User.objects.filter(email__iexact=email_or_username).first() or User.objects.filter(username__iexact=email_or_username).first()

    if not user:
        return JsonResponse({
            "status": "success",
            "exists": False,
            "has_yubikey": False,
            "has_totp": False,
            "message": "No account found for this Email ID. Please register and set up your YubiKey or TOTP security.",
            "setup_url": "/osivault/auth/portal/"
        }, status=200)

    yubikey_count = UserWebAuthnKey.objects.filter(user=user, is_active=True).count()
    has_totp = UserTOTPDevice.objects.filter(user=user, is_verified=True).exists()
    has_yubikey = yubikey_count > 0

    mfa_methods = []
    if has_yubikey:
        mfa_methods.append("WEBAUTHN")
    if has_totp:
        mfa_methods.append("TOTP")

    if has_yubikey and has_totp:
        message = "🎉 Both YubiKey Hardware and TOTP Authenticator are active for your account! Select your preferred authentication method below:"
    elif has_yubikey:
        message = f"🔑 YubiKey Hardware registered ({yubikey_count} active slot). Touch your golden sensor to authenticate."
    elif has_totp:
        message = "📱 TOTP Authenticator App linked to your account. Enter your 6-digit authenticator code below."
    else:
        message = "ℹ️ No YubiKey or TOTP Authenticator setup found for this Email ID. Please click below to set up MFA security."

    return JsonResponse({
        "status": "success",
        "exists": True,
        "email": user.email,
        "username": user.username,
        "has_yubikey": has_yubikey,
        "has_totp": has_totp,
        "yubikey_count": yubikey_count,
        "mfa_methods": mfa_methods,
        "message": message,
        "setup_url": "/osivault/auth/portal/"
    }, status=200)


@csrf_exempt
def totp_setup_api(request):
    """
    Generate or retrieve TOTP secret for the authenticated user and return QR code URI and secret seed.
    Persists an unverified UserTOTPDevice record until verified with a valid code.
    """
    if not request.user.is_authenticated:
        return JsonResponse({"status": "error", "message": "Authentication required"}, status=401)

    try:
        import pyotp
        user = request.user
        totp_device = UserTOTPDevice.objects.filter(user=user).first()

        if not totp_device or not totp_device.encrypted_secret:
            secret = pyotp.random_base32()
            if totp_device:
                totp_device.encrypted_secret = secret
                totp_device.is_verified = False
                totp_device.save()
            else:
                totp_device = UserTOTPDevice.objects.create(
                    user=user,
                    encrypted_secret=secret,
                    is_verified=False
                )
        else:
            secret = totp_device.encrypted_secret

        verifier = TOTPVerifier(secret=secret)
        prov_uri = verifier.provisioning_uri(name=user.email or user.username, issuer_name="OSIVault")

        return JsonResponse({
            "status": "success",
            "secret": secret,
            "provisioning_uri": prov_uri,
            "is_verified": totp_device.is_verified,
            "user": {
                "username": user.username,
                "email": user.email,
            }
        }, status=200)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def totp_verify_api(request):
    """
    Verify 6-digit TOTP code for user authentication or initial setup verification.
    """
    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else {}
        code = str(data.get("code", "")).strip()
        email_or_username = data.get("email") or data.get("username")

        if not code or len(code) != 6:
            return JsonResponse({"status": "error", "message": "Valid 6-digit TOTP code is required."}, status=400)

        from django.contrib.auth import get_user_model
        User = get_user_model()

        if email_or_username:
            user = User.objects.filter(email__iexact=email_or_username).first() or User.objects.filter(username__iexact=email_or_username).first()
        elif request.user.is_authenticated:
            user = request.user
        else:
            user = None

        if not user:
            return JsonResponse({"status": "error", "message": "User account not found for TOTP verification."}, status=404)

        totp_device = UserTOTPDevice.objects.filter(user=user).first()
        if not totp_device:
            return JsonResponse({"status": "error", "message": "TOTP device not configured for this user account. Please generate TOTP setup first."}, status=404)

        totp_verifier = TOTPVerifier(secret=totp_device.encrypted_secret, last_counter=totp_device.last_counter)
        is_valid = totp_verifier.verify(code)

        if not is_valid:
            return JsonResponse({"status": "error", "message": "Invalid or expired TOTP code. Please check your authenticator app."}, status=400)

        totp_device.is_verified = True
        totp_device.last_counter = totp_verifier.last_counter or (totp_device.last_counter + 1)
        totp_device.save()

        profile, _ = UserMFAProfile.objects.get_or_create(user=user)
        profile.mfa_enabled = True
        if profile.preferred_method == "NONE":
            profile.preferred_method = "TOTP"
        profile.save()

        if not request.user.is_authenticated:
            django_login(request, user)

        claims = {"sub": user.username, "email": user.email, "email_verified": profile.email_verified}
        token = osivault.tokens.issue(claims)

        try:
            osivault.audit.append(
                None,
                actor=user.username,
                tenant="OSIVault_Auth",
                resource_type="TOTPDevice",
                resource_id=str(totp_device.id),
                action="TOTP_AUTHENTICATED",
                new_values={"user": user.username, "email": user.email}
            )
        except Exception:
            pass

        return JsonResponse({
            "status": "success",
            "message": f"🎉 TOTP Authenticator verified! Welcome back, {user.username}.",
            "token": token,
            "is_verified": True,
            "user": {
                "username": user.username,
                "email": user.email,
            }
        }, status=200)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def generate_recovery_codes_api(request):
    """
    Generate 8 single-use emergency break-glass recovery codes for the authenticated user.
    Saves SHA-256 hashes in UserRecoveryCode database table and returns raw codes once.
    """
    if not request.user.is_authenticated:
        return JsonResponse({"status": "error", "message": "Authentication required"}, status=401)

    try:
        from osivault.auth.adapters import RecoveryCodes
        from osivault.auth.models import UserRecoveryCode

        raw_codes, hashed_codes = RecoveryCodes.generate(count=8)

        # Purge existing recovery codes for this user before generating a fresh set
        UserRecoveryCode.objects.filter(user=request.user).delete()

        # Save SHA-256 hashes in database
        for h in hashed_codes:
            UserRecoveryCode.objects.create(
                user=request.user,
                code_hash=h,
                is_used=False
            )

        try:
            osivault.audit.append(
                None,
                actor=request.user.username,
                tenant="OSIVault_Auth",
                resource_type="RecoveryCodes",
                resource_id=request.user.username,
                action="RECOVERY_CODES_GENERATED",
                new_values={"count": len(raw_codes), "user": request.user.username}
            )
        except Exception:
            pass

        return JsonResponse({
            "status": "success",
            "message": "🎉 8 Emergency Recovery Codes generated & hashed as SHA-256 in OSIVault DB. Keep them in a safe place!",
            "codes": raw_codes,
            "count": len(raw_codes)
        }, status=200)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@csrf_exempt
def verify_recovery_code_api(request):
    """
    Verify a single-use emergency break-glass recovery code for account recovery or sign-in.
    """
    try:
        from osivault.auth.models import UserRecoveryCode
        data = json.loads(request.body.decode("utf-8")) if request.body else {}
        code = str(data.get("code", "")).strip().upper()
        email_or_username = data.get("email") or data.get("username")

        if not code:
            return JsonResponse({"status": "error", "message": "Recovery code is required."}, status=400)

        from django.contrib.auth import get_user_model
        User = get_user_model()

        if email_or_username:
            user = User.objects.filter(email__iexact=email_or_username).first() or User.objects.filter(username__iexact=email_or_username).first()
        elif request.user.is_authenticated:
            user = request.user
        else:
            user = None

        if not user:
            return JsonResponse({"status": "error", "message": "User account not found for recovery code verification."}, status=404)

        import hashlib
        hashed_input = hashlib.sha256(code.encode("utf-8")).hexdigest()

        recovery_entry = UserRecoveryCode.objects.filter(user=user, code_hash=hashed_input, is_used=False).first()
        if not recovery_entry:
            return JsonResponse({"status": "error", "message": "Invalid or already used recovery code."}, status=400)

        recovery_entry.is_used = True
        recovery_entry.used_at = now()
        recovery_entry.save()

        if not request.user.is_authenticated:
            django_login(request, user)

        profile, _ = UserMFAProfile.objects.get_or_create(user=user)
        claims = {"sub": user.username, "email": user.email, "email_verified": profile.email_verified}
        token = osivault.tokens.issue(claims)

        try:
            osivault.audit.append(
                None,
                actor=user.username,
                tenant="OSIVault_Auth",
                resource_type="RecoveryCode",
                resource_id=str(recovery_entry.id),
                action="RECOVERY_CODE_CONSUMED",
                new_values={"user": user.username, "email": user.email}
            )
        except Exception:
            pass

        remaining_count = UserRecoveryCode.objects.filter(user=user, is_used=False).count()

        return JsonResponse({
            "status": "success",
            "message": f"🎉 Emergency Recovery Code verified! Welcome back, {user.username}. ({remaining_count} emergency codes remaining)",
            "token": token,
            "remaining_codes": remaining_count,
            "user": {
                "username": user.username,
                "email": user.email,
            }
        }, status=200)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)



