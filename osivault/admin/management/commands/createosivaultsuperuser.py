"""
Django Management Command to create an OSIVault Superuser / Admin Account.
Usage:
    python manage.py createosivaultsuperuser
    python manage.py createosivaultsuperuser --email admin@onesmarter.com --password SecretPass123! --role superuser
"""

import getpass
from django.core.management.base import BaseCommand, CommandError
from osivault.admin.auth import create_admin_account
from osivault.admin.models import OSIVaultAdminAccount


class Command(BaseCommand):
    help = "Creates a new OSIVault Administrator Account (Superuser) for Desktop Admin Panel."

    def add_arguments(self, parser):
        parser.add_argument(
            "--email",
            dest="email",
            default=None,
            help="Specifies the work email for the OSIVault superuser.",
        )
        parser.add_argument(
            "--password",
            dest="password",
            default=None,
            help="Specifies the password for the OSIVault superuser.",
        )
        parser.add_argument(
            "--role",
            dest="role",
            default="superuser",
            help="Specifies the administrative role (default: superuser).",
        )
        parser.add_argument(
            "--noinput",
            "--no-input",
            action="store_false",
            dest="interactive",
            default=True,
            help="Tells Django to NOT prompt the user for input.",
        )

    def handle(self, *args, **options):
        email = options.get("email")
        password = options.get("password")
        role = options.get("role") or "superuser"
        interactive = options.get("interactive")

        if not interactive:
            if not email or not password:
                raise CommandError("--email and --password are required when using --noinput.")
        else:
            self.stdout.write(self.style.MIGRATE_HEADING("=" * 65))
            self.stdout.write(self.style.MIGRATE_HEADING("  OSIVault Superuser Account Creation"))
            self.stdout.write(self.style.MIGRATE_HEADING("=" * 65))

            # Interactive Email Input
            while not email:
                input_email = input("Work email address: ").strip()
                if not input_email:
                    self.stderr.write("Error: Email address cannot be blank.")
                    continue
                if OSIVaultAdminAccount.objects.filter(email=input_email).exists():
                    self.stderr.write(f"Error: An OSIVault admin account with email '{input_email}' already exists.")
                    continue
                email = input_email

            # Interactive Password Input
            while not password:
                raw_p1 = getpass.getpass("Password: ")
                if not raw_p1:
                    self.stderr.write("Error: Password cannot be blank.")
                    continue
                raw_p2 = getpass.getpass("Password (again): ")
                if raw_p1 != raw_p2:
                    self.stderr.write("Error: Passwords do not match. Please try again.")
                    continue
                password = raw_p1

        try:
            account = create_admin_account(email=email, password=password, role=role)
            self.stdout.write(
                self.style.SUCCESS(
                    f"[SUCCESS] OSIVault Superuser Account '{account.email}' ({account.role}) created successfully!"
                )
            )
        except Exception as e:
            raise CommandError(f"Failed to create OSIVault superuser: {e}")
