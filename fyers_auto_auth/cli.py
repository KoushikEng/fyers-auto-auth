"""Command-line interface for fyers-auto-auth.

Usage::

    $ fyers-auto-auth generate-key [--output PATH]
    $ fyers-auto-auth setup-app --client-id ID --secret-key KEY [--redirect-uri URI] [--no-browser]
"""

import argparse
import sys

from fyers_auto_auth.encryption import DEFAULT_KEY_FILE, generate_fernet_key
from fyers_auto_auth.setup_app import DEFAULT_REDIRECT_URI, setup_app


def _cmd_generate_key(args):
    """Handle the ``generate-key`` sub-command."""
    output = args.output or str(DEFAULT_KEY_FILE)
    key = generate_fernet_key(save_to=output)
    print(f"Fernet key generated successfully.")
    print(f"Key : {key.decode()}")
    print(f"Saved to: {output}")


def _cmd_setup_app(args):
    """Handle the ``setup-app`` sub-command."""
    setup_app(
        client_id=args.client_id,
        secret_key=args.secret_key,
        redirect_uri=args.redirect_uri,
        open_browser=not args.no_browser,
    )


def main(argv=None):
    """Entry point for the ``fyers-auto-auth`` CLI."""
    parser = argparse.ArgumentParser(
        prog="fyers-auto-auth",
        description="Automated Fyers broker access token generation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── generate-key ───────────────────────────────────────────────────
    key_parser = subparsers.add_parser(
        "generate-key",
        help="Generate a new Fernet encryption key.",
    )
    key_parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help=f"Path to save the key file (default: {DEFAULT_KEY_FILE}).",
    )

    # ── setup-app ──────────────────────────────────────────────────────
    setup_parser = subparsers.add_parser(
        "setup-app",
        help="First-time Fyers API app authorization.",
    )
    setup_parser.add_argument(
        "--client-id",
        required=True,
        help='Fyers API app client ID (e.g. "L9NY305RTW-100").',
    )
    setup_parser.add_argument(
        "--secret-key",
        required=True,
        help="Fyers API app secret key.",
    )
    setup_parser.add_argument(
        "--redirect-uri",
        default=DEFAULT_REDIRECT_URI,
        help=f"Redirect URI (default: {DEFAULT_REDIRECT_URI}).",
    )
    setup_parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Don't auto-open the URL in the browser.",
    )

    args = parser.parse_args(argv)

    if args.command == "generate-key":
        _cmd_generate_key(args)
    elif args.command == "setup-app":
        _cmd_setup_app(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
