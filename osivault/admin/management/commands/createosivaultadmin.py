"""
Alias command for python manage.py createosivaultadmin
"""

from osivault.admin.management.commands.createosivaultsuperuser import Command as BaseCommand


class Command(BaseCommand):
    help = "Creates a new OSIVault Admin Account for Desktop Admin Panel."
