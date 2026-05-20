"""
fyers-auto-auth: Automated Fyers broker access token generation with encrypted storage.

Handles the complete TOTP-based login flow, generates access tokens,
and caches them encrypted on disk — refreshing automatically each day.
"""

from fyers_auto_auth.auth import FyersAuth
from fyers_auto_auth.encryption import generate_fernet_key, load_fernet_key
from fyers_auto_auth.setup_app import setup_app

__all__ = ["FyersAuth", "generate_fernet_key", "load_fernet_key", "setup_app"]
__version__ = "0.1.0"
