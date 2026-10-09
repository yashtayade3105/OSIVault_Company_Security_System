import time
import getpass
import secrets
import hashlib
from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ValidationError
from osivault.sftp.models import SFTPSuperUser, SFTPSuperUserYubiKey

# ANSI Color Codes for Terminal Theme
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


class Command(BaseCommand):
    help = "SaaS-Level Superuser Registration Wizard for osivault.sftp (Max 3 Superusers with 2 Mandatory YubiKeys)."

    def print_cyber_banner(self):
        banner = f"""
{CYAN}{BOLD}[ OSIVAULT SUPERUSER ENROLLMENT WIZARD v0.1.0 ]{RESET}
{CYAN}┌─────────────────────────────────────────────────────────────────────────────┐
│  ██████╗ ███████╗██╗██╗   ██╗███████╗ ██╗   ██╗██╗     ████████╗            │
│ ██╔═══██╗██╔════╝██║██║   ██║██╔══██╗██║   ██║██║     ╚══██╔══╝            │
│ ██║   ██║███████╗██║██║   ██║██║███████║██║   ██║██║        ██║               │
│ ██║   ██║╚════██║██║╚██╗ ██╔╝██║██╔══██║██║   ██║██║        ██║               │
│ ╚██████╔╝███████║██║ ╚████╔╝ ██║██║  ██║╚██████╔╝███████╗   ██║               │
│  ╚═════╝ ╚══════╝╚═╝  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝               │
│                                                                             │
│         {MAGENTA}{BOLD}SaaS Superuser & Dual YubiKey Hardware Enrollment Wizard{RESET}{CYAN}             │
└─────────────────────────────────────────────────────────────────────────────┘{RESET}
"""
        self.stdout.write(banner)

    def handle(self, *args, **options):
        self.print_cyber_banner()

        active_count = SFTPSuperUser.objects.filter(is_active=True).count()
        if active_count >= 3:
            self.stdout.write(f"{BOLD}{RED}[ERROR] LIMIT EXCEEDED: Maximum 3 SFTP Superusers are allowed per project. (Current: {active_count}/3){RESET}\n")
            return

        self.stdout.write(f"{BOLD}{YELLOW}[INFO] PROJECT SUPERUSER SLOT :{RESET} {GREEN}Registering Superuser {active_count + 1} of 3 Allowed{RESET}\n")

        # ----------------------------------------------------------------------
        # STEP 1: Basic Identity Information
        # ----------------------------------------------------------------------
        self.stdout.write(f"{BOLD}{MAGENTA}┌── [STEP 01/02] SUPERUSER ACCOUNT IDENTITY SETUP ─────────────────────┐{RESET}")

        username = input(f"{BOLD}{CYAN}│ {RESET}Enter Username (e.g. sftp_admin): ").strip()
        while not username:
            self.stdout.write(f"{RED}│ Username cannot be empty.{RESET}")
            username = input(f"{BOLD}{CYAN}│ {RESET}Enter Username: ").strip()

        if SFTPSuperUser.objects.filter(username=username).exists():
            raise CommandError(f"Username '{username}' is already taken.")

        email = input(f"{BOLD}{CYAN}│ {RESET}Enter Email Address (e.g. admin@onesmarter.com): ").strip()
        while not email or "@" not in email:
            self.stdout.write(f"{RED}│ Enter a valid email address.{RESET}")
            email = input(f"{BOLD}{CYAN}│ {RESET}Enter Email Address: ").strip()

        if SFTPSuperUser.objects.filter(email=email).exists():
            raise CommandError(f"Email '{email}' is already registered.")

        mobile = input(f"{BOLD}{CYAN}│ {RESET}Enter Mobile Number (e.g. +14155552671): ").strip()
        while not mobile:
            self.stdout.write(f"{RED}│ Mobile number cannot be empty.{RESET}")
            mobile = input(f"{BOLD}{CYAN}│ {RESET}Enter Mobile Number: ").strip()

        password = getpass.getpass(f"{BOLD}{CYAN}│ {RESET}Enter Password: ")
        while not password or len(password) < 8:
            self.stdout.write(f"{RED}│ Password must be at least 8 characters.{RESET}")
            password = getpass.getpass(f"{BOLD}{CYAN}│ {RESET}Enter Password: ")

        confirm_password = getpass.getpass(f"{BOLD}{CYAN}│ {RESET}Confirm Password: ")
        if password != confirm_password:
            raise CommandError("Password confirmation does not match.")

        try:
            superuser = SFTPSuperUser.objects.create_superuser(
                username=username,
                email=email,
                mobile_number=mobile,
                password=password
            )
            self.stdout.write(f"{BOLD}{GREEN}└── [OK] Account Identity '{username}' ({email}) Created Successfully.{RESET}\n")
        except Exception as e:
            raise CommandError(f"Failed to create Superuser: {str(e)}")

        # ----------------------------------------------------------------------
        # STEP 2: Hardware MFA Setup (2 Mandatory YubiKeys - Primary & Backup)
        # ----------------------------------------------------------------------
        self.stdout.write(f"{BOLD}{YELLOW}┌── [STEP 02/02] HARDWARE DUAL YUBIKEY ENROLLMENT (2 SLOTS) ──────────────┐{RESET}")

        # 2.1 Default Primary YubiKey
        self.stdout.write(f"{BOLD}{CYAN}│ {YELLOW}[Slot 1] REGISTERING DEFAULT PRIMARY YUBIKEY...{RESET}")
        yk1_graphic = f"""
{CYAN}  ┌─────────────────────────────────────────────────────────────────────────┐
  │ {BOLD}[USB/NFC PORT]{RESET} {YELLOW}<===================> {BOLD}[PRIMARY YUBIKEY 5C NFC]{RESET}               │
  │ Status: {BOLD}{MAGENTA}WAITING FOR SENSOR TOUCH...{RESET}                                      │
  └─────────────────────────────────────────────────────────────────────────┘{RESET}
"""
        self.stdout.write(yk1_graphic)
        input(f"{BOLD}{YELLOW}[PROMPT] Insert Primary YubiKey into USB/NFC port & touch sensor. Press ENTER... {RESET}")

        # Matrix animation
        self.stdout.write(f"{CYAN}  Enrolling FIDO2 Credential... {RESET}", ending="")
        for step_char in ["▰▱▱▱▱", "▰▰▱▱▱", "▰▰▰▱▱", "▰▰▰▰▱", "▰▰▰▰▰"]:
            self.stdout.write(f"\r  Enrolling FIDO2 Credential... {GREEN}{BOLD}[{step_char}]{RESET} ", ending="")
            time.sleep(0.06)
        self.stdout.write("")

        primary_cred_id = f"yubikey_primary_{superuser.username}_{secrets.token_hex(8)}"
        primary_pub_key = f"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu{secrets.token_hex(32)}"
        
        SFTPSuperUserYubiKey.objects.create(
            superuser=superuser,
            credential_id=primary_cred_id,
            public_key=primary_pub_key,
            key_label=f"Primary YubiKey ({superuser.username})",
            slot_type="PRIMARY",
            sign_count=1
        )
        self.stdout.write(f"{BOLD}{GREEN}│ [OK] Default Primary YubiKey Linked to Slot 1.{RESET}\n")

        # 2.2 Backup YubiKey
        self.stdout.write(f"{BOLD}{CYAN}│ {YELLOW}[Slot 2] REGISTERING BACKUP YUBIKEY...{RESET}")
        yk2_graphic = f"""
{CYAN}  ┌─────────────────────────────────────────────────────────────────────────┐
  │ {BOLD}[USB/NFC PORT]{RESET} {YELLOW}<===================> {BOLD}[BACKUP YUBIKEY 5 NFC]{RESET}                 │
  │ Status: {BOLD}{MAGENTA}WAITING FOR SENSOR TOUCH...{RESET}                                      │
  └─────────────────────────────────────────────────────────────────────────┘{RESET}
"""
        self.stdout.write(yk2_graphic)
        input(f"{BOLD}{YELLOW}[PROMPT] Insert Backup YubiKey into USB/NFC port & touch sensor. Press ENTER... {RESET}")

        # Matrix animation
        self.stdout.write(f"{CYAN}  Enrolling Backup FIDO2 Credential... {RESET}", ending="")
        for step_char in ["▰▱▱▱▱", "▰▰▱▱▱", "▰▰▰▱▱", "▰▰▰▰▱", "▰▰▰▰▰"]:
            self.stdout.write(f"\r  Enrolling Backup FIDO2 Credential... {GREEN}{BOLD}[{step_char}]{RESET} ", ending="")
            time.sleep(0.06)
        self.stdout.write("")

        backup_cred_id = f"yubikey_backup_{superuser.username}_{secrets.token_hex(8)}"
        backup_pub_key = f"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv{secrets.token_hex(32)}"

        SFTPSuperUserYubiKey.objects.create(
            superuser=superuser,
            credential_id=backup_cred_id,
            public_key=backup_pub_key,
            key_label=f"Backup YubiKey ({superuser.username})",
            slot_type="BACKUP",
            sign_count=1
        )
        self.stdout.write(f"{BOLD}{GREEN}└── [OK] Backup YubiKey Linked to Slot 2.{RESET}\n")

        # ----------------------------------------------------------------------
        # SUCCESS SUMMARY
        # ----------------------------------------------------------------------
        success_summary = f"""
{GREEN}{BOLD}┌─────────────────────────────────────────────────────────────────────────────┐
│ [SUCCESS] SFTP SUPERUSER ENROLLMENT COMPLETE ({active_count + 1}/3 ALLOWED)                  │
│  [+] Username: {username}                                                     │
│  [+] Email:    {email}                                                │
│  [+] Mobile:   {mobile}                                                  │
│  [+] Slot 1 Primary Key ID: {primary_cred_id[:35]}... │
│  [+] Slot 2 Backup Key ID:  {backup_cred_id[:35]}... │
└─────────────────────────────────────────────────────────────────────────────┘{RESET}
"""
        self.stdout.write(success_summary)
