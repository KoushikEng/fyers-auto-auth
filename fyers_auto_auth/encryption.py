"""Fernet encryption key generation and loading utilities."""

import os
from pathlib import Path

from cryptography.fernet import Fernet

__all__ = ["generate_fernet_key", "load_fernet_key"]

DEFAULT_KEY_DIR = Path.home() / ".fyers_auto_auth"
DEFAULT_KEY_FILE = DEFAULT_KEY_DIR / "fernet.key"


def generate_fernet_key(save_to=None):
    """Generate a new Fernet encryption key.

    Args:
        save_to: Optional path (str or Path) to save the key file.
            Parent directories are created automatically.
            The ``~`` shorthand is expanded.

    Returns:
        bytes: The generated Fernet key.

    Example::

        from fyers_auto_auth import generate_fernet_key

        # Generate and keep in memory
        key = generate_fernet_key()

        # Generate and persist to disk
        key = generate_fernet_key(save_to="~/.fyers_auto_auth/fernet.key")
    """
    key = Fernet.generate_key()

    if save_to is not None:
        path = Path(save_to).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(key)

    return key


def load_fernet_key(path=None):
    """Load a Fernet encryption key from a file or environment variable.

    Resolution order:

    1. Explicit *path* argument.
    2. ``FYERS_FERNET_KEY`` environment variable (the raw key value).
    3. ``FYERS_FERNET_KEY_FILE`` environment variable (path to a key file).
    4. Default location: ``~/.fyers_auto_auth/fernet.key``.

    Args:
        path: Optional explicit path to the key file.

    Returns:
        bytes: The Fernet key.

    Raises:
        FileNotFoundError: If no key could be located via any of the above.
        ValueError: If the ``FYERS_FERNET_KEY`` env var is set but empty.
    """
    # 1. Explicit path
    if path is not None:
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Key file not found: {resolved}")
        return resolved.read_bytes().strip()

    # 2. Direct key value from env
    env_key = os.environ.get("FYERS_FERNET_KEY")
    if env_key is not None:
        env_key = env_key.strip()
        if not env_key:
            raise ValueError("FYERS_FERNET_KEY environment variable is set but empty.")
        return env_key.encode() if isinstance(env_key, str) else env_key

    # 3. Key file path from env
    env_file = os.environ.get("FYERS_FERNET_KEY_FILE")
    if env_file:
        resolved = Path(env_file).expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(
                f"Key file specified by FYERS_FERNET_KEY_FILE not found: {resolved}"
            )
        return resolved.read_bytes().strip()

    # 4. Default path
    if DEFAULT_KEY_FILE.exists():
        return DEFAULT_KEY_FILE.read_bytes().strip()

    raise FileNotFoundError(
        "No Fernet key found. Provide one by:\n"
        "  1. Passing the 'path' argument to load_fernet_key()\n"
        "  2. Setting the FYERS_FERNET_KEY env var (raw key value)\n"
        "  3. Setting the FYERS_FERNET_KEY_FILE env var (path to key file)\n"
        f"  4. Placing a key file at the default location: {DEFAULT_KEY_FILE}\n\n"
        "Generate a new key with:\n"
        "  $ fyers-auto-auth generate-key\n"
        "  or: from fyers_auto_auth import generate_fernet_key; generate_fernet_key(save_to='~/.fyers_auto_auth/fernet.key')"
    )
