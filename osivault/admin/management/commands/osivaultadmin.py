"""
Django Management Command to launch the OSIVault Desktop Admin Panel GUI.
Usage:
    python manage.py osivaultadmin
"""

import sys
import subprocess
from pathlib import Path
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Launches the OSIVault Desktop Admin Panel Native Application GUI."

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING("=" * 65))
        self.stdout.write(self.style.MIGRATE_HEADING("  Launching OSIVault Desktop Admin Panel..."))
        self.stdout.write(self.style.MIGRATE_HEADING("=" * 65))

        base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
        app_script = base_dir / "desktop_admin" / "app.py"
        exe_file = base_dir / "dist" / "OSIVaultAdmin" / "OSIVaultAdmin.exe"

        if app_script.exists():
            self.stdout.write(self.style.SUCCESS(f"[LAUNCH] Executing Live OSIVault Admin GUI: {app_script}"))
            subprocess.Popen([sys.executable, str(app_script)])
        elif exe_file.exists():
            self.stdout.write(self.style.SUCCESS(f"[LAUNCH] Executing Desktop Executable: {exe_file}"))
            subprocess.Popen([str(exe_file)])
        else:
            self.stderr.write("Error: Could not locate OSIVault Desktop App executable or launcher script.")
