import os
from django.conf import settings

def get_sftp_vault_directory():
    """
    Universally resolves the SFTP Vault Directory for osivault.sftp across any OS or server environment.
    Priority order:
    1. OS Environment Variable: OSIVAULT_SFTP_DIRECTORY or SERVER_VAULT_DIRECTORY
    2. Django Settings: settings.SERVER_VAULT_DIRECTORY
    3. Local Dev Default: D:\Transfers\Server_Directory (if directory exists)
    4. Fallback Default: media/server_directory in BASE_DIR or os.getcwd()/server_directory
    """
    env_dir = os.environ.get("OSIVAULT_SFTP_DIRECTORY") or os.environ.get("SERVER_VAULT_DIRECTORY")
    if env_dir:
        os.makedirs(env_dir, exist_ok=True)
        return os.path.abspath(env_dir)

    settings_dir = getattr(settings, "SERVER_VAULT_DIRECTORY", None)
    if settings_dir:
        os.makedirs(settings_dir, exist_ok=True)
        return os.path.abspath(settings_dir)

    dev_default = r"D:\Transfers\Server_Directory"
    if os.path.exists(dev_default):
        return os.path.abspath(dev_default)

    base_dir = getattr(settings, "BASE_DIR", None)
    if base_dir:
        fallback = os.path.join(base_dir, "media", "server_directory")
    else:
        fallback = os.path.join(os.getcwd(), "server_directory")

    os.makedirs(fallback, exist_ok=True)
    return os.path.abspath(fallback)
