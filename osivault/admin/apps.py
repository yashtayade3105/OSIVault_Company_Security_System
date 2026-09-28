"""
Django AppConfig for osivault.admin module.
"""

from django.apps import AppConfig


class OSIVaultAdminConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "osivault.admin"
    label = "osivault_admin"
    verbose_name = "OSIVault Admin System"
