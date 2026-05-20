"""Tests for the fyers-auto-auth CLI."""

import pytest
from fyers_auto_auth.cli import main


class TestCLIGenerateKey:
    """Tests for the generate-key sub-command."""

    def test_generate_key_creates_file(self, tmp_path):
        output = tmp_path / "cli_key.key"
        main(["generate-key", "--output", str(output)])
        assert output.exists()
        assert len(output.read_bytes()) == 44

    def test_generate_key_default_output(self, tmp_path, monkeypatch):
        """Ensure it works with the default output path (patched)."""
        import fyers_auto_auth.encryption as enc
        default = tmp_path / "fernet.key"
        monkeypatch.setattr(enc, "DEFAULT_KEY_FILE", default)
        # Re-import cli so it picks up the patched default
        from fyers_auto_auth import cli as cli_mod
        monkeypatch.setattr(cli_mod, "DEFAULT_KEY_FILE", default)
        main(["generate-key"])
        assert default.exists()


class TestCLIHelp:
    """Test that --help doesn't crash."""

    def test_root_help(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_generate_key_help(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["generate-key", "--help"])
        assert exc_info.value.code == 0

    def test_setup_app_help(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["setup-app", "--help"])
        assert exc_info.value.code == 0

    def test_no_args_exits(self):
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code != 0
