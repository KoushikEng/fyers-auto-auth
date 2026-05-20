"""Tests for the FyersAuth class (initialization and path resolution only).

These tests do NOT hit the Fyers API — they validate constructor logic,
token path resolution, and encryption round-trips.
"""

import json
import os
import datetime
import pytest

from fyers_auto_auth import FyersAuth
from fyers_auto_auth.encryption import generate_fernet_key


@pytest.fixture
def fernet_key():
    """Generate a fresh Fernet key for each test."""
    return generate_fernet_key()


@pytest.fixture
def auth_kwargs(fernet_key):
    """Minimal valid kwargs for FyersAuth (won't make real API calls)."""
    return dict(
        client_id="TESTAPP-100",
        secret_key="test_secret",
        username="TE0001",
        totp_key="JBSWY3DPEHPK3PXP",
        pin="1234",
        encryption_key=fernet_key,
    )


class TestFyersAuthInit:
    """Test FyersAuth constructor and configuration."""

    def test_basic_init(self, auth_kwargs):
        auth = FyersAuth(**auth_kwargs)
        assert auth is not None

    def test_accepts_bytes_key(self, auth_kwargs):
        auth_kwargs["encryption_key"] = generate_fernet_key()  # bytes
        auth = FyersAuth(**auth_kwargs)
        assert auth is not None

    def test_accepts_str_key(self, auth_kwargs):
        auth_kwargs["encryption_key"] = generate_fernet_key().decode()  # str
        auth = FyersAuth(**auth_kwargs)
        assert auth is not None

    def test_custom_redirect_uri(self, auth_kwargs):
        auth_kwargs["redirect_uri"] = "https://example.com/callback"
        auth = FyersAuth(**auth_kwargs)
        assert auth is not None


class TestTokenPathResolution:
    """Test that token_file path is resolved correctly."""

    def test_explicit_path(self, auth_kwargs, tmp_path):
        custom_path = tmp_path / "custom_tokens.json"
        auth_kwargs["token_file"] = str(custom_path)
        auth = FyersAuth(**auth_kwargs)
        # Access the mangled private attribute to verify
        resolved = auth._FyersAuth__token_file
        assert resolved == custom_path

    def test_env_var_path(self, auth_kwargs, tmp_path, monkeypatch):
        env_path = tmp_path / "env_tokens.json"
        monkeypatch.setenv("FYERS_TOKEN_FILE", str(env_path))
        auth = FyersAuth(**auth_kwargs)
        resolved = auth._FyersAuth__token_file
        assert resolved == env_path

    def test_explicit_overrides_env(self, auth_kwargs, tmp_path, monkeypatch):
        explicit = tmp_path / "explicit.json"
        env = tmp_path / "env.json"
        monkeypatch.setenv("FYERS_TOKEN_FILE", str(env))
        auth_kwargs["token_file"] = str(explicit)
        auth = FyersAuth(**auth_kwargs)
        resolved = auth._FyersAuth__token_file
        assert resolved == explicit

    def test_default_path(self, auth_kwargs, monkeypatch):
        monkeypatch.delenv("FYERS_TOKEN_FILE", raising=False)
        auth = FyersAuth(**auth_kwargs)
        resolved = auth._FyersAuth__token_file
        assert str(resolved).endswith(".fyers_auto_auth/tokens.json")


class TestTokenEncryptionRoundTrip:
    """Test that token encryption/decryption works correctly via save/load."""

    def test_save_and_load_token(self, auth_kwargs, tmp_path):
        token_file = tmp_path / "tokens.json"
        auth_kwargs["token_file"] = str(token_file)
        auth = FyersAuth(**auth_kwargs)

        # Simulate saving a token
        today = datetime.date.today().strftime("%Y-%m-%d")
        test_token = {"access_token": "TESTAPP-100:eyJhbGciOiJIUzI1NiJ9.test", "date": today}
        auth._FyersAuth__save_token(test_token)

        assert token_file.exists()

        # Load and verify
        loaded = auth._FyersAuth__load_token()
        assert loaded is not None
        assert loaded["access_token"] == test_token["access_token"]
        assert loaded["date"] == today

    def test_load_missing_file_returns_none(self, auth_kwargs, tmp_path):
        auth_kwargs["token_file"] = str(tmp_path / "nonexistent.json")
        auth = FyersAuth(**auth_kwargs)
        assert auth._FyersAuth__load_token() is None

    def test_load_wrong_key_returns_none(self, auth_kwargs, tmp_path):
        """Decrypting with a different key should return None (not crash)."""
        token_file = tmp_path / "tokens.json"
        auth_kwargs["token_file"] = str(token_file)

        # Save with key A
        auth_a = FyersAuth(**auth_kwargs)
        today = datetime.date.today().strftime("%Y-%m-%d")
        auth_a._FyersAuth__save_token({"access_token": "secret_token", "date": today})

        # Try to load with key B
        auth_kwargs["encryption_key"] = generate_fernet_key()
        auth_b = FyersAuth(**auth_kwargs)
        assert auth_b._FyersAuth__load_token() is None

    def test_save_creates_parent_dirs(self, auth_kwargs, tmp_path):
        token_file = tmp_path / "deep" / "nested" / "tokens.json"
        auth_kwargs["token_file"] = str(token_file)
        auth = FyersAuth(**auth_kwargs)
        auth._FyersAuth__save_token({"access_token": "tok", "date": "2026-01-01"})
        assert token_file.exists()

    def test_saved_file_is_encrypted(self, auth_kwargs, tmp_path):
        """The raw JSON on disk should NOT contain the plaintext token."""
        token_file = tmp_path / "tokens.json"
        auth_kwargs["token_file"] = str(token_file)
        auth = FyersAuth(**auth_kwargs)
        plaintext = "MY_SUPER_SECRET_TOKEN_VALUE"
        auth._FyersAuth__save_token({"access_token": plaintext, "date": "2026-01-01"})

        raw = token_file.read_text()
        assert plaintext not in raw
        data = json.loads(raw)
        assert data["access_token"] != plaintext
        assert data["date"] == "2026-01-01"
