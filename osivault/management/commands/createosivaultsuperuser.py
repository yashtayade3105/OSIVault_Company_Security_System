"""
Django Management Command to create an OSIVault Superuser.
Alias pointing to osivault.admin command.
"""

from osivault.admin.management.commands.createosivaultsuperuser import Command as BaseCommand


class Command(BaseCommand):
    pass
