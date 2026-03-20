import os
import re
import datetime

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes raw filenames to prevent path traversal or special character injection.
    Currently, the Vault stores files by their SHA-256 hash, which is implicitly safe,
    but this function adds defense-in-depth for original filenames.
    """
    # Remove any path separators
    filename = os.path.basename(filename)
    # Allow only word characters, dashes, and dots
    return re.sub(r'[^\w\.-]', '_', filename)

def cleanup_vault(vault_dir: str, days_old: int = 30):
    """
    Automated cleanup script to remove artifacts older than a certain number of days 
    to prevent disk exhaustion.
    """
    if not os.path.exists(vault_dir):
        return

    now = datetime.datetime.now()
    cutoff_time = now - datetime.timedelta(days=days_old)

    for root, dirs, files in os.walk(vault_dir):
        for file in files:
            if file == ".gitkeep":
                 continue
            file_path = os.path.join(root, file)
            file_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
            if file_mtime < cutoff_time:
                try:
                    os.remove(file_path)
                    print(f"Removed old artifact: {file_path}")
                except Exception as e:
                    print(f"Failed to remove {file_path}: {e}")
