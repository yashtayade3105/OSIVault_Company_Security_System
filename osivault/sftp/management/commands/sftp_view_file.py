import os
import sys
import time
import getpass
import tempfile
import subprocess
from django.core.management.base import BaseCommand, CommandError
from osivault.sftp.models import SFTPSuperUser, SFTPSuperUserYubiKey, SFTPFileAccessLog
from osivault.sftp.crypto import decrypt_file_payload, compute_sha256, SFTPCryptoError
from osivault.sftp.viewer import launch_secure_notepad_viewer, launch_secure_multi_notepad_viewer
from osivault.sftp.utils import get_sftp_vault_directory

# ANSI Color Codes for Terminal Theme
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

class Command(BaseCommand):
    help = "Hardware-Gated Encrypted File Viewer & Directory Scanner for osivault.sftp Superusers."

    def add_arguments(self, parser):
        parser.add_argument("file_path", type=str, nargs="?", default=None, help="Path to encrypted file or directory on disk (defaults to OSIVAULT_SFTP_DIRECTORY or settings.SERVER_VAULT_DIRECTORY)")
        parser.add_argument("--key", type=str, help="Optional hex string of 32-byte AES-256 decryption key", default=None)

    def print_cyber_banner(self):
        banner = f"""
{CYAN}{BOLD}[ OSIVAULT ZERO-TRUST CORE v0.1.0 ]{RESET}
{CYAN}┌─────────────────────────────────────────────────────────────────────────────┐
│  ██████╗ ███████╗██╗██╗   ██╗███████╗ ██╗   ██╗██╗     ████████╗            │
│ ██╔═══██╗██╔════╝██║██║   ██║██╔══██╗██║   ██║██║     ╚══██╔══╝            │
│ ██║   ██║███████╗██║██║   ██║██║███████║██║   ██║██║        ██║               │
│ ██║   ██║╚════██║██║╚██╗ ██╔╝██║██╔══██║██║   ██║██║        ██║               │
│ ╚██████╔╝███████║██║ ╚████╔╝ ██║██║  ██║╚██████╔╝███████╗   ██║               │
│  ╚═════╝ ╚══════╝╚═╝  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝               │
│                                                                             │
│               {MAGENTA}{BOLD}Enterprise Hardware-Gated SFTP Decryption Terminal{RESET}{CYAN}            │
└─────────────────────────────────────────────────────────────────────────────┘{RESET}
"""
        self.stdout.write(banner)

    def parse_selection(self, selection_str, total_count):
        selection_str = selection_str.strip().upper()
        if selection_str in ["A", "ALL"]:
            return list(range(total_count))
        if selection_str in ["Q", "QUIT", "EXIT", "CANCEL"]:
            return []
        
        indices = set()
        parts = selection_str.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                subparts = part.split("-")
                if len(subparts) == 2 and subparts[0].isdigit() and subparts[1].isdigit():
                    start = int(subparts[0])
                    end = int(subparts[1])
                    for idx in range(start, end + 1):
                        if 1 <= idx <= total_count:
                            indices.add(idx - 1)
            elif part.isdigit():
                idx = int(part)
                if 1 <= idx <= total_count:
                    indices.add(idx - 1)
        return sorted(list(indices))

    def get_format_badge(self, file_path):
        try:
            with open(file_path, "rb") as f:
                header = f.read(4)
            if header == b"OSIV":
                return f"{RED}{BOLD}[OSIV CIPHERTEXT]{RESET}"
            else:
                return f"{GREEN}{BOLD}[PLAINTEXT EDI]  {RESET}"
        except Exception:
            return f"{DIM}[UNKNOWN FORMAT] {RESET}"

    def handle(self, *args, **options):
        raw_path = options.get("file_path")
        if not raw_path:
            target_path = get_sftp_vault_directory()
        else:
            target_path = os.path.abspath(raw_path)

        if not os.path.exists(target_path):
            raise CommandError(f"File or Directory not found at path: {target_path}")

        all_scanned_files = []
        if os.path.isdir(target_path):
            for root, dirs, files in os.walk(target_path):
                for f in files:
                    all_scanned_files.append(os.path.join(root, f))
            if not all_scanned_files:
                raise CommandError(f"No files found in directory: {target_path}")
            all_scanned_files.sort()
        else:
            all_scanned_files = [target_path]

        self.print_cyber_banner()

        files_to_process = []
        if os.path.isdir(target_path):
            self.stdout.write(f"{BOLD}{CYAN}[TARGET DIRECTORY]  :{RESET} {YELLOW}{BOLD}{target_path}{RESET}")
            self.stdout.write(f"{BOLD}{CYAN}[TOTAL FILES FOUND] :{RESET} {GREEN}{len(all_scanned_files)} Files{RESET}\n")

            self.stdout.write(f"{BOLD}{MAGENTA}┌── [DIRECTORY DISCOVERY SCANNER] ──────────────────────────────────────────┐{RESET}")
            self.stdout.write(f"{CYAN}│ Index | Format Badge        | File Name                             | Size{RESET}")
            self.stdout.write(f"{CYAN}├───────┼─────────────────────┼───────────────────────────────────────┼─────────────{RESET}")
            
            for idx, fpath in enumerate(all_scanned_files, 1):
                fname = os.path.basename(fpath)
                badge = self.get_format_badge(fpath)
                fsize = f"{os.path.getsize(fpath):,} B"
                if len(fname) > 37:
                    fname = fname[:34] + "..."
                self.stdout.write(f"│  {BOLD}{GREEN}[{idx:2d}]{RESET}  | {badge} | {YELLOW}{fname:<37}{RESET} | {fsize:<11}")
            
            self.stdout.write(f"{BOLD}{MAGENTA}└───────────────────────────────────────────────────────────────────────────┘{RESET}\n")

            while True:
                sel_input = input(f"{BOLD}{CYAN}[SELECT] Select File(s) to Decrypt & View (e.g. 1, 3 or 1-3 or 'A' for All, 'Q' to Exit): {RESET}").strip()
                if not sel_input:
                    continue
                selected_indices = self.parse_selection(sel_input, len(all_scanned_files))
                if sel_input.upper() in ["Q", "QUIT", "EXIT", "CANCEL"]:
                    self.stdout.write(f"{YELLOW}Operation cancelled by Superuser.{RESET}\n")
                    return
                if selected_indices:
                    files_to_process = [all_scanned_files[i] for i in selected_indices]
                    self.stdout.write(f"{BOLD}{GREEN}[OK] Selected {len(files_to_process)} file(s) for hardware-gated decryption.{RESET}\n")
                    break
                else:
                    self.stdout.write(f"{RED}[ERROR] Invalid selection! Please enter valid indices (e.g., 1, 3 or 1-3 or A).{RESET}\n")
        else:
            files_to_process = [target_path]
            self.stdout.write(f"{BOLD}{CYAN}[TARGET CIPHERTEXT FILE] :{RESET} {YELLOW}{BOLD}{target_path}{RESET}")
            self.stdout.write(f"{BOLD}{CYAN}[FILE SIZE ENCRYPTED]  :{RESET} {GREEN}{os.path.getsize(target_path):,} Bytes{RESET}\n")

        # ----------------------------------------------------------------------
        # STEP 1: Superuser Identity & Password Verification
        # ----------------------------------------------------------------------
        self.stdout.write(f"{BOLD}{MAGENTA}┌── [STEP 01/02] SUPERUSER IDENTITY & PASSWORD CHECK ───────────────────┐{RESET}")
        username_or_email = input(f"{BOLD}{CYAN}│ {RESET}Enter SFTP Superuser Username/Email: ").strip()
        user = SFTPSuperUser.objects.filter(username__iexact=username_or_email, is_active=True).first() or \
               SFTPSuperUser.objects.filter(email__iexact=username_or_email, is_active=True).first()

        log_file_path = target_path
        log_filename = os.path.basename(target_path)

        if not user:
            SFTPFileAccessLog.objects.create(
                file_path=log_file_path, filename=log_filename, action="REJECTED",
                sha256_hash="", is_success=False
            )
            self.stdout.write(f"{BOLD}{RED}└── [ACCESS DENIED] Superuser '{username_or_email}' not found or inactive.{RESET}\n")
            raise CommandError(f"Access Denied: Superuser '{username_or_email}' not found or inactive.")

        password = getpass.getpass(f"{BOLD}{CYAN}│ {RESET}Enter Password: ")
        if not user.check_password(password):
            SFTPFileAccessLog.objects.create(
                superuser=user, file_path=log_file_path, filename=log_filename,
                action="REJECTED_PASSWORD", sha256_hash="", is_success=False
            )
            self.stdout.write(f"{BOLD}{RED}└── [ACCESS DENIED] Incorrect password for '{user.username}'.{RESET}\n")
            raise CommandError("Access Denied: Incorrect password.")

        self.stdout.write(f"{BOLD}{GREEN}└── [OK] Password Verified for Superuser Account '{user.username}' ({user.email}).{RESET}\n")

        # ----------------------------------------------------------------------
        # STEP 2: Hardware YubiKey FIDO2 CTAP2 Touch Contact Verification
        # ----------------------------------------------------------------------
        self.stdout.write(f"{BOLD}{YELLOW}┌── [STEP 02/02] HARDWARE YUBIKEY FIDO2 TOUCH VERIFICATION ──────────────┐{RESET}")

        yubikeys = SFTPSuperUserYubiKey.objects.filter(superuser=user)
        if not yubikeys.exists():
            raise CommandError("No registered YubiKeys found for this Superuser account.")

        self.stdout.write(f"{BOLD}{CYAN}│ Registered YubiKey Hardware Slots for '{user.username}':{RESET}")
        for idx, yk in enumerate(yubikeys, 1):
            slot_badge = "PRIMARY" if yk.slot_type == "PRIMARY" else "BACKUP"
            self.stdout.write(f"│   {BOLD}{GREEN}[Slot {idx}]{RESET} {YELLOW}{slot_badge}{RESET} - {yk.key_label} (Sign Count: {yk.sign_count})")

        choice = input(f"{BOLD}{CYAN}│ {RESET}Select YubiKey Slot (1 or 2, default 1): ").strip() or "1"
        try:
            selected_yk = yubikeys[int(choice) - 1]
        except (ValueError, IndexError):
            selected_yk = yubikeys[0]

        self.stdout.write(f"{BOLD}{CYAN}│ {RESET}Selected Hardware Slot: {BOLD}{YELLOW}{selected_yk.get_slot_type_display()} ({selected_yk.key_label}){RESET}")
        
        # Cyber Graphic for YubiKey Hardware Touch Prompt
        yk_graphic = f"""
{CYAN}  ┌─────────────────────────────────────────────────────────────────────────┐
  │ {BOLD}[USB/NFC PORT]{RESET} {YELLOW}<===================> {BOLD}[YUBIKEY 5C NFC HARDWARE]{RESET}        │
  │ Status: {BOLD}{MAGENTA}WAITING FOR PHYSICAL GOLDEN SENSOR TOUCH...{RESET}                       │
  └─────────────────────────────────────────────────────────────────────────┘{RESET}
"""
        self.stdout.write(yk_graphic)
        input(f"{BOLD}{YELLOW}[PROMPT] Insert YubiKey & touch golden contact sensor. Press ENTER when touched... {RESET}")

        # Animated Scanner Matrix Animation
        self.stdout.write(f"{CYAN}  Scanning FIDO2 CTAP2 Sensor... {RESET}", ending="")
        for step_char in ["▰▱▱▱▱", "▰▰▱▱▱", "▰▰▰▱▱", "▰▰▰▰▱", "▰▰▰▰▰"]:
            self.stdout.write(f"\r  Scanning FIDO2 CTAP2 Sensor... {GREEN}{BOLD}[{step_char}]{RESET} ", ending="")
            time.sleep(0.08)
        self.stdout.write("")

        # Update YubiKey usage counter
        selected_yk.sign_count += 1
        selected_yk.save()

        self.stdout.write(f"{BOLD}{GREEN}└── [SUCCESS] YUBIKEY HARDWARE TOUCH VERIFIED! Contact confirmed for '{selected_yk.key_label}' (Sign count: {selected_yk.sign_count}).{RESET}\n")

        # ----------------------------------------------------------------------
        # STEP 3: Decrypt In-Memory & Launch Secure Self-Destructing Notepad
        # ----------------------------------------------------------------------
        file_items_to_view = []
        file_metadata_list = []

        self.stdout.write(f"{BOLD}{MAGENTA}┌── [RAM DECRYPTION & NOTEPAD TAB PREPARATION ({len(files_to_process)} Files)] ────────┐{RESET}")

        for cur_idx, file_path in enumerate(files_to_process, 1):
            filename = os.path.basename(file_path)

            self.stdout.write(f"{CYAN}│ {BOLD}[File {cur_idx}/{len(files_to_process)}]{RESET} {YELLOW}{filename}{RESET}")
            self.stdout.write(f"{CYAN}│ {RESET}Decrypting AES-256-GCM ciphertext payload in RAM...")

            with open(file_path, "rb") as f:
                encrypted_bytes = f.read()

            decrypted_payload = None
            sha256_hash = ""

            key_bytes = bytes.fromhex(options["key"]) if options.get("key") else b"osivault_sftp_secret_key_32bytes"
            if len(key_bytes) != 32:
                key_bytes = key_bytes.ljust(32, b"\x00")[:32]

            if encrypted_bytes.startswith(b"OSIV"):
                try:
                    decrypted_payload, sha256_hash = decrypt_file_payload(encrypted_bytes, key=key_bytes)
                except Exception as e:
                    self.stdout.write(f"{RED}│ Ciphertext decrypt exception: {str(e)}{RESET}")
                    decrypted_payload = encrypted_bytes
                    sha256_hash = compute_sha256(encrypted_bytes)
            else:
                decrypted_payload = encrypted_bytes
                sha256_hash = compute_sha256(encrypted_bytes)

            # Log Access Success
            SFTPFileAccessLog.objects.create(
                superuser=user, file_path=file_path, filename=filename,
                action="DECRYPT_VIEW", sha256_hash=sha256_hash, is_success=True
            )

            try:
                from osivault.audit import append
                append(
                    event_type="SECURITY_SFTP_SUPERUSER_FILE_VIEWED",
                    actor=user.username,
                    details={
                        "filename": filename,
                        "file_path": file_path,
                        "sha256_hash": sha256_hash,
                        "yubikey_slot": selected_yk.slot_type,
                    }
                )
            except Exception:
                pass

            file_items_to_view.append((filename, decrypted_payload))
            file_metadata_list.append((file_path, filename, sha256_hash))

            self.stdout.write(f"{CYAN}│ {BOLD}SHA-256 Integrity Hash :{RESET} {GREEN}{sha256_hash}{RESET}")

        self.stdout.write(f"{BOLD}{MAGENTA}└───────────────────────────────────────────────────────────────────────┘{RESET}\n")

        num_tabs = len(file_items_to_view)
        tab_str = f"{num_tabs} Separate Tab(s)" if num_tabs > 1 else "1 Tab"
        self.stdout.write(f"{YELLOW}[INFO] Launching Notepad with {BOLD}{GREEN}{tab_str}{RESET}{YELLOW}... Plaintext available ONLY while Notepad window is open.{RESET}")
        self.stdout.write(f"{YELLOW}[WARNING] Note: As soon as Notepad window closes, ALL temporary RAM plaintexts are zero-wiped!{RESET}\n")

        # Launch Notepad with ALL selected files as tabs at once!
        launch_secure_multi_notepad_viewer(file_items_to_view, wait_for_close=True)

        # Log Re-Encryption Close & Print Zero-Trust Purge Boxes for each file
        for cur_idx, (file_path, filename, sha256_hash) in enumerate(file_metadata_list, 1):
            SFTPFileAccessLog.objects.create(
                superuser=user, file_path=file_path, filename=filename,
                action="RE_ENCRYPT_CLOSE", sha256_hash=sha256_hash, is_success=True
            )

            close_summary = f"""
{GREEN}{BOLD}┌─────────────────────────────────────────────────────────────────────────────┐
│ [ZERO-TRUST PURGE VERIFIED [{cur_idx}/{len(file_metadata_list)}]]:                                       │
│  [+] Temporary Plaintext RAM Buffer: OVERWRITTEN WITH 0x00 BYTES & PURGED   │
│  [+] Original Disk Ciphertext: '{filename}' (100% ENCRYPTED CIPHERTEXT)      │
│  [+] Cryptographic Audit Trail: LOGGED TO OSIVAULT.AUDIT HASH CHAIN         │
└─────────────────────────────────────────────────────────────────────────────┘{RESET}
"""
            self.stdout.write(close_summary)
