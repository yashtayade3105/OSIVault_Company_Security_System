from django.apps import AppConfig


class AuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "osivault.auth"
    label = "osivault_auth"
    verbose_name = "OSIVault Auth Module"
