"""
osivault.auth: Second-factor adapters for privileged and ordinary accounts.
Provides TOTP verification, WebAuthn registration & assertion, Recovery Code generators, and Email OTP verification adapters.
"""

import pyotp
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Tuple, Dict, Any, Optional


class AuthError(Exception):
    """Base exception for osivault.auth adapters."""
    pass


class EmailOTPAdapter:
    """
    Secure 6-Digit Email OTP Generator, Dispatcher, and Verifier adapter.
    Integrates with Django's django.core.mail.send_mail for real SMTP/SendGrid delivery.
    Enforces 10-minute expiration, max 5 verification attempts, and single-use consumption.
    """
    @staticmethod
    def generate_otp(email: str, purpose: str = "REGISTRATION", expiry_minutes: int = 10) -> Dict[str, Any]:
        email = str(email).strip().lower()
        if not email or "@" not in email:
            raise AuthError("Invalid email address provided for OTP generation.")
        
        # Generate cryptographically secure 6-digit numeric OTP
        otp_code = str(secrets.randbelow(900000) + 100000)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
        
        from osivault.auth.models import EmailOTPVerification
        # Deactivate previous unverified OTPs for this email & purpose
        EmailOTPVerification.objects.filter(email=email, purpose=purpose, is_verified=False).delete()
        
        EmailOTPVerification.objects.create(
            email=email,
            otp_code=otp_code,
            purpose=purpose,
            expires_at=expires_at,
        )

        # Attempt real email dispatch via Django Core Mail send_mail
        email_dispatched = False
        try:
            from django.core.mail import send_mail
            from django.conf import settings
            sender = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@osivault.com")
            send_mail(
                subject="OSIVault Security: Your 6-Digit Verification Code",
                message=(
                    f"Hello,\n\n"
                    f"Your OSIVault 6-digit verification code is: {otp_code}\n\n"
                    f"This code will expire in {expiry_minutes} minutes. "
                    f"If you did not request this verification, please ignore this email.\n\n"
                    f"Regards,\nOSIVault Security Core"
                ),
                from_email=sender,
                recipient_list=[email],
                fail_silently=True,
            )
            email_dispatched = True
        except Exception:
            email_dispatched = False
        
        return {
            "status": "success",
            "email": email,
            "otp_code": otp_code,
            "email_dispatched": email_dispatched,
            "expires_at": expires_at.isoformat(),
            "message": f"6-Digit verification code generated for {email}. Valid for {expiry_minutes} minutes."
        }

    @staticmethod
    def verify_otp(email: str, otp_code: str, purpose: str = "REGISTRATION") -> Tuple[bool, str]:
        email = str(email).strip().lower()
        otp_code = str(otp_code).strip()
        
        if not email or not otp_code or len(otp_code) != 6 or not otp_code.isdigit():
            return False, "Invalid email or OTP code format. Enter a 6-digit number."
            
        from osivault.auth.models import EmailOTPVerification
        now = datetime.now(timezone.utc)
        record = EmailOTPVerification.objects.filter(
            email=email,
            purpose=purpose,
            is_verified=False
        ).order_by("-created_at").first()
        
        if not record:
            return False, "No active OTP verification request found for this email."
            
        if record.attempts >= 5:
            return False, "Maximum verification attempts exceeded. Please request a new OTP."
            
        if record.expires_at < now:
            return False, "OTP code has expired. Please request a new verification code."
            
        if record.otp_code != otp_code:
            record.attempts += 1
            record.save()
            return False, f"Incorrect verification code. ({5 - record.attempts} attempts remaining)"
            
        record.is_verified = True
        record.save()
        return True, "Email address verified successfully!"


class TOTPVerifier:
    """
    TOTP (Time-based One-Time Password) verifier with replay protection.
    Defaults valid_window to 0 and enforces last-counter replay guard.
    """
    def __init__(self, secret: str = None, last_counter: Optional[int] = None):
        self.secret = secret or pyotp.random_base32()
        self.totp = pyotp.TOTP(self.secret)
        self.last_counter: Optional[int] = last_counter

    def generate_otp(self) -> str:
        return self.totp.now()

    def verify(
        self,
        otp_code: str,
        valid_window: int = 0,
        last_counter: Optional[int] = None,
        for_time: Optional[datetime] = None,
    ) -> bool:
        if not otp_code or not str(otp_code).isdigit():
            return False

        now = for_time or datetime.now(timezone.utc)
        current_counter = self.totp.timecode(now)
        min_counter = last_counter if last_counter is not None else self.last_counter

        if min_counter is not None and current_counter <= min_counter:
            return False

        verified = self.totp.verify(str(otp_code), valid_window=valid_window, for_time=now)
        if verified:
            self.last_counter = current_counter
            return True

        return False

    def provisioning_uri(self, name: str, issuer_name: str = "OSIVault") -> str:
        return self.totp.provisioning_uri(name=name, issuer_name=issuer_name)

    def qr_code_base64(self, name: str, issuer_name: str = "OSIVault") -> str:
        import io
        import base64
        import qrcode
        uri = self.provisioning_uri(name=name, issuer_name=issuer_name)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64_str = base64.b64encode(buf.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{b64_str}"


class WebAuthnRegistrar:
    """
    WebAuthn / FIDO2 Hardware Key Registration adapter.
    """
    def __init__(self, rp_id: str, rp_name: str = "OSIVault Core"):
        self.rp_id = rp_id
        self.rp_name = rp_name

    def generate_registration_options(self, username: str, user_id: bytes | str | None = None, rp_id: str = None, rp_name: str = None) -> Dict[str, Any]:
        from osivault.auth.webauthn import generate_registration_options
        return generate_registration_options(
            username=username,
            rp_id=rp_id or self.rp_id,
            user_id=user_id,
            rp_name=rp_name or self.rp_name,
        )

    def verify_registration_response(
        self,
        response_data: Dict[str, Any],
        expected_challenge: bytes | str,
        expected_rp_id: str = None,
        expected_origin: str = None,
    ) -> Dict[str, Any]:
        from osivault.auth.webauthn import verify_registration_response
        rpid = expected_rp_id or self.rp_id
        orig = expected_origin or f"https://{rpid}"
        return verify_registration_response(
            response_data=response_data,
            expected_challenge=expected_challenge,
            expected_rp_id=rpid,
            expected_origin=orig,
        )


class WebAuthnAsserter:
    """
    WebAuthn / FIDO2 Hardware Key Authentication Asserter adapter.
    """
    def __init__(self, rp_id: str):
        self.rp_id = rp_id

    def generate_assertion_options(self, credential_ids: List[str] | str, rp_id: str = None) -> Dict[str, Any]:
        from osivault.auth.webauthn import generate_assertion_options
        return generate_assertion_options(
            credential_ids=credential_ids,
            rp_id=rp_id or self.rp_id,
        )

    def verify_assertion_response(
        self,
        credential_id: str,
        authenticator_data_b64: str,
        client_data_json_b64: str,
        signature_b64: str,
        challenge_b64: str,
        public_key_b64: str,
        expected_rp_id: str = None,
        expected_origin: str = None,
        current_sign_count: int = 0,
    ) -> Dict[str, Any]:
        from osivault.auth.webauthn import verify_assertion_response
        rpid = expected_rp_id or self.rp_id
        orig = expected_origin or f"https://{rpid}"
        return verify_assertion_response(
            credential_id=credential_id,
            authenticator_data_b64=authenticator_data_b64,
            client_data_json_b64=client_data_json_b64,
            signature_b64=signature_b64,
            challenge_b64=challenge_b64,
            public_key_b64=public_key_b64,
            expected_rp_id=rpid,
            expected_origin=orig,
            current_sign_count=current_sign_count,
        )


class RecoveryCodes:
    """
    Secure single-use emergency recovery code generator and hasher.
    """
    @staticmethod
    def generate(count: int = 8, code_length: int = 10) -> Tuple[List[str], List[str]]:
        raw_codes = []
        hashed_codes = []
        for _ in range(count):
            raw = secrets.token_hex(code_length // 2).upper()
            raw_formatted = f"{raw[:5]}-{raw[5:]}"
            raw_codes.append(raw_formatted)
            hashed_codes.append(hashlib.sha256(raw_formatted.encode("utf-8")).hexdigest())
        return raw_codes, hashed_codes

    @staticmethod
    def verify(raw_code: str, hashed_codes: List[str]) -> Tuple[bool, List[str]]:
        raw_code = str(raw_code).strip().upper()
        hashed_input = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
        if hashed_input in hashed_codes:
            updated_list = [h for h in hashed_codes if h != hashed_input]
            return True, updated_list
        return False, hashed_codes
