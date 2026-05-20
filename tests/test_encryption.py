"""Tests for the fyers_auto_auth.encryption module."""

import os
import pytest

from fyers_auto_auth.encryption import generate_fernet_key, load_fernet_key


class TestGenerateFernetKey:
    """Tests for generate_fernet_key()."""

    def test_returns_bytes(self):
        key = generate_fernet_key()
        assert isinstance(key, bytes)

    def test_key_length(self):
        """Fernet keys are 44 bytes URL-safe base64."""
        key = generate_fernet_key()
        assert len(key) == 44

    def test_unique_keys(self):
        """Each call should produce a unique key."""
        k1 = generate_fernet_key()
        k2 = generate_fernet_key()
        assert k1 != k2

    def test_save_to_file(self, tmp_path):
        key_file = tmp_path / "test.key"
        key = generate_fernet_key(save_to=str(key_file))
        assert key_file.exists()
        assert key_file.read_bytes() == key

    def test_save_creates_parent_dirs(self, tmp_path):
        key_file = tmp_path / "deep" / "nested" / "dir" / "test.key"
        generate_fernet_key(save_to=str(key_file))
        assert key_file.exists()


class TestLoadFernetKey:
    """Tests for load_fernet_key()."""

    def test_load_from_explicit_path(self, tmp_path):
        key_file = tmp_path / "test.key"
        original_key = generate_fernet_key(save_to=str(key_file))
        loaded_key = load_fernet_key(path=str(key_file))
        assert loaded_key == original_key

    def test_load_from_missing_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_fernet_key(path=str(tmp_path / "nonexistent.key"))

    def test_load_from_env_var_direct_key(self, tmp_path, monkeypatch):
        key = generate_fernet_key()
        monkeypatch.setenv("FYERS_FERNET_KEY", key.decode())
        # Also unset the file env var to avoid interference
        monkeypatch.delenv("FYERS_FERNET_KEY_FILE", raising=False)
        loaded = load_fernet_key()
        assert loaded == key

    def test_load_from_env_var_empty_raises(self, monkeypatch):
        monkeypatch.setenv("FYERS_FERNET_KEY", "  ")
        monkeypatch.delenv("FYERS_FERNET_KEY_FILE", raising=False)
        with pytest.raises(ValueError, match="empty"):
            load_fernet_key()

    def test_load_from_env_var_file_path(self, tmp_path, monkeypatch):
        key_file = tmp_path / "env_key.key"
        original_key = generate_fernet_key(save_to=str(key_file))
        monkeypatch.delenv("FYERS_FERNET_KEY", raising=False)
        monkeypatch.setenv("FYERS_FERNET_KEY_FILE", str(key_file))
        loaded = load_fernet_key()
        assert loaded == original_key

    def test_load_from_env_var_file_missing_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FYERS_FERNET_KEY", raising=False)
        monkeypatch.setenv("FYERS_FERNET_KEY_FILE", str(tmp_path / "nope.key"))
        with pytest.raises(FileNotFoundError, match="FYERS_FERNET_KEY_FILE"):
            load_fernet_key()

    def test_no_key_anywhere_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FYERS_FERNET_KEY", raising=False)
        monkeypatch.delenv("FYERS_FERNET_KEY_FILE", raising=False)
        # Patch the default path to a location that doesn't exist
        import fyers_auto_auth.encryption as enc
        monkeypatch.setattr(enc, "DEFAULT_KEY_FILE", tmp_path / "missing.key")
        with pytest.raises(FileNotFoundError, match="No Fernet key found"):
            load_fernet_key()

    def test_env_priority_direct_over_file(self, tmp_path, monkeypatch):
        """FYERS_FERNET_KEY (direct) should take priority over FYERS_FERNET_KEY_FILE."""
        direct_key = generate_fernet_key()
        file_key = generate_fernet_key(save_to=str(tmp_path / "file.key"))
        monkeypatch.setenv("FYERS_FERNET_KEY", direct_key.decode())
        monkeypatch.setenv("FYERS_FERNET_KEY_FILE", str(tmp_path / "file.key"))
        loaded = load_fernet_key()
        assert loaded == direct_key
        assert loaded != file_key
