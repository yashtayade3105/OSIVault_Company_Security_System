import hashlib
from django.db import models
from django.core.exceptions import ValidationError
from django.utils.timezone import now
from django.contrib.auth.hashers import make_password, check_password


class SFTPSuperUserManager(models.Manager):
    def create_superuser(self, username, email, mobile_number, password):
        if SFTPSuperUser.objects.filter(is_active=True).count() >= 3:
            raise ValidationError("Maximum limit of 3 SFTP Superusers reached for this project.")
            
        superuser = self.model(
            username=username.strip(),
            email=email.strip().lower(),
            mobile_number=mobile_number.strip(),
            password_hash=make_password(password),
            is_active=True
        )
        superuser.full_clean()
        superuser.save()
        return superuser


class SFTPSuperUser(models.Model):
    """
    SaaS-Level SFTP Superuser Model.
    Enforces a strict maximum limit of 3 Superusers per project.
    """
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    mobile_number = models.CharField(max_length=20)
    password_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=now)
    is_active = models.BooleanField(default=True)

    objects = SFTPSuperUserManager()

    class Meta:
        verbose_name = "SFTP Superuser"
        verbose_name_plural = "SFTP Superusers"
        ordering = ["-created_at"]

    def clean(self):
        super().clean()
        if not self.pk and SFTPSuperUser.objects.filter(is_active=True).count() >= 3:
            raise ValidationError("Maximum limit of 3 SFTP Superusers reached for this project.")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password_hash)

    def set_password(self, raw_password: str):
        self.password_hash = make_password(raw_password)

    def __str__(self):
        return f"SFTP Superuser ({self.username} - {self.email})"


class SFTPSuperUserYubiKey(models.Model):
    """
    YubiKey Hardware Credential Model for SFTP Superusers.
    Supports 2 mandatory slots: Primary YubiKey and Backup YubiKey.
    """
    SLOT_CHOICES = [
        ("PRIMARY", "Default Primary YubiKey"),
        ("BACKUP", "Backup YubiKey"),
    ]

    superuser = models.ForeignKey(SFTPSuperUser, on_delete=models.CASCADE, related_name="yubikeys")
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()
    key_label = models.CharField(max_length=100)
    slot_type = models.CharField(max_length=10, choices=SLOT_CHOICES, default="PRIMARY")
    sign_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=now)

    class Meta:
        verbose_name = "SFTP Superuser YubiKey"
        verbose_name_plural = "SFTP Superuser YubiKeys"
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.superuser.username} - {self.get_slot_type_display()} ({self.key_label})"


class SFTPFileAccessLog(models.Model):
    """
    Audit Trail Log for SFTP File Access and Hardware-Gated Decryption Events.
    """
    superuser = models.ForeignKey(SFTPSuperUser, on_delete=models.SET_NULL, null=True, blank=True)
    file_path = models.CharField(max_length=1024)
    filename = models.CharField(max_length=255)
    action = models.CharField(max_length=50) # DECRYPT_VIEW, RE_ENCRYPT_CLOSE, REJECTED
    sha256_hash = models.CharField(max_length=64)
    timestamp = models.DateTimeField(default=now)
    is_success = models.BooleanField(default=True)

    class Meta:
        verbose_name = "SFTP File Access Log"
        verbose_name_plural = "SFTP File Access Logs"
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.action} - {self.filename} ({'SUCCESS' if self.is_success else 'FAILED'})"
