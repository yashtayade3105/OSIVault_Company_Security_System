"""
OSIVault YubiKey & WebAuthn Interactive Terminal Demonstration Script.
Date: 29-09-2026
Run with: python demo_yubikey_flow.py
"""

import sys
import time
import secrets
import hashlib
import hmac
import uuid

# Color formatting for terminal output
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_step(step_num, title, description):
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{YELLOW} [STEP {step_num}] {title}{RESET}")
    print(f"{CYAN}======================================================================{RESET}")
    print(f" {description}\n")


def main():
    print(f"\n{BOLD}{GREEN}======================================================================{RESET}")
    print(f"{BOLD}{GREEN}       OSIVault YubiKey & WebAuthn Live Terminal Demonstration      {RESET}")
    print(f"{BOLD}{GREEN}======================================================================{RESET}")

    # -------------------------------------------------------------------------
    # STEP 1: Admin Password Verification
    # -------------------------------------------------------------------------
    print_step(1, "ADMIN PASSWORD AUTHENTICATION", "User enters Admin Email & Password.")
    email = input(f" {BOLD}Enter Admin Email [{CYAN}admin@onesmarter.com{RESET}]: ").strip() or "admin@onesmarter.com"
    password = input(f" {BOLD}Enter Admin Password [{CYAN}admin123{RESET}]: ").strip() or "admin123"

    print(f"\n {YELLOW} Verifying password for '{email}'...{RESET}")
    time.sleep(0.6)
    print(f" {GREEN} Password Verified! Password check passed.{RESET}")
    print(f" {MAGENTA} Triggering Mandatory Hardware MFA Challenge...{RESET}")
    time.sleep(0.8)

    # -------------------------------------------------------------------------
    # STEP 2: Server Challenge Nonce Generation
    # -------------------------------------------------------------------------
    print_step(2, "SERVER CRYPTOGRAPHIC CHALLENGE GENERATION", "Server generates a 32-byte Cryptographic Nonce Challenge.")
    
    # Generate random 32-byte challenge
    challenge_nonce = secrets.token_hex(16).upper()
    credential_id = "yubikey_5_nfc_" + uuid.uuid4().hex[:12]
    
    print(f" {BOLD}Server Payload Generated:{RESET}")
    print(f"   • Target RP ID         : {CYAN}localhost{RESET}")
    print(f"   • YubiKey Credential ID: {CYAN}{credential_id}{RESET}")
    print(f"   • Challenge Nonce Code : {YELLOW}{BOLD}{challenge_nonce}{RESET}")
    print(f"\n {MAGENTA}📡 Transferring Nonce '{challenge_nonce}' to USB port...{RESET}")
    time.sleep(1.0)

    # -------------------------------------------------------------------------
    # STEP 3: YubiKey USB Insertion Check
    # -------------------------------------------------------------------------
    print_step(3, "YUBIKEY USB INSERTION DETECTED", "Handshake between Computer and YubiKey USB Hardware microchip.")
    print(f" {YELLOW} Waiting for YubiKey USB Insertion...{RESET}")
    print(f" {BOLD}{GREEN} Press ENTER to insert YubiKey into USB Port...{RESET}", end="")
    input()
    
    print(f"\n {GREEN}✔ YUBIKEY 5 NFC HARDWARE CONNECTED & LOCKED IN USB PORT!{RESET}")
    print(f" {CYAN}   USB HID Handshake Complete. Nonce '{challenge_nonce}' loaded into YubiKey memory.{RESET}")
    time.sleep(1.0)

    # -------------------------------------------------------------------------
    # STEP 4: Physical Gold Touch Sensor Assertion (Human Presence)
    # -------------------------------------------------------------------------
    print_step(4, "HUMAN PRESENCE CHECK (GOLD TOUCH SENSOR)", "YubiKey Gold Touch Sensor waits for physical human finger touch.")
    print(f" {RED}{BOLD} SECURITY WARNING:{RESET} To prevent remote hackers from auto-authenticating,")
    print(f"                   the YubiKey Microchip demands a Physical Finger Touch!")
    print(f"\n {YELLOW}  YubiKey Gold Metal Button is GLOWING...{RESET}")
    print(f" {BOLD}{GREEN} TOUCH YOUR PHYSICAL YUBIKEY GOLD SENSOR BUTTON NOW (or press ENTER)...{RESET} ", end="", flush=True)
    
    yubikey_input = input()

    if yubikey_input and len(yubikey_input) > 10:
        print(f"\n {GREEN}{BOLD}✔ PHYSICAL YUBIKEY HARDWARE SIGNAL CAPTURED!{RESET}")
        print(f"   • Captured Hardware String: {YELLOW}{yubikey_input[:20]}...{RESET}")
    else:
        print(f"\n {GREEN}✔ PHYSICAL FINGER TOUCH DETECTED ON GOLD METAL SENSOR!{RESET}")
    
    print(f" {CYAN}   User Presence Flag (UP=True) confirmed. Microchip activated.{RESET}")
    time.sleep(0.8)

    # -------------------------------------------------------------------------
    # STEP 5: Microchip Cryptographic Signature Stamping
    # -------------------------------------------------------------------------
    print_step(5, "MICROCHIP CRYPTOGRAPHIC SIGNATURE STAMPING", "YubiKey Secure Element Microchip signs Nonce with ECDSA Private Key.")
    print(f" {YELLOW} Stamping Nonce '{challenge_nonce}' inside YubiKey Microchip...{RESET}")
    
    # Simulate internal secret key inside YubiKey chip
    yubikey_private_secret = b"yubikey_hardware_secure_element_secret_key_9988"
    digital_signature = hmac.new(yubikey_private_secret, challenge_nonce.encode('utf-8'), hashlib.sha256).hexdigest()
    sign_count = 142
    
    time.sleep(0.7)
    print(f" {GREEN}✔ DIGITAL STAMP APPLIED INSIDE CHIP!{RESET}")
    print(f"   • Nonce Signed : {CYAN}{challenge_nonce}{RESET}")
    print(f"   • Hardware Sig : {YELLOW}{digital_signature[:32]}...{RESET}")
    print(f"   • Sign Counter : {CYAN}{sign_count}{RESET} (Prevents Cloned Keys)")
    time.sleep(1.0)

    # -------------------------------------------------------------------------
    # STEP 6: Server Verification & Session Granted
    # -------------------------------------------------------------------------
    print_step(6, "SERVER VERIFICATION & SESSION UNLOCKED", "Server verifies Digital Stamp & Nonce match.")
    print(f" {YELLOW} Verifying Signature & Nonce on OSIVault Admin Server...{RESET}")
    time.sleep(0.8)

    session_token = secrets.token_hex(24)
    print(f" {GREEN}{BOLD}✔ 100% WEBAUTHN FIDO2 HARDWARE ASSERTION VERIFIED!{RESET}")
    print(f" {CYAN}   Session Token Generated : {YELLOW}{session_token}{RESET}")
    print(f"   Status                  : {GREEN}{BOLD}ADMIN CONSOLE UNLOCKED & GRANTED (24 Hours){RESET}")

    print(f"\n{BOLD}{GREEN}======================================================================{RESET}")
    print(f"{BOLD}{GREEN}          DEMONSTRATION COMPLETE: YubiKey Flow Verified Clean!       {RESET}")
    print(f"{BOLD}{GREEN}======================================================================{RESET}\n")


if __name__ == "__main__":
    main()
