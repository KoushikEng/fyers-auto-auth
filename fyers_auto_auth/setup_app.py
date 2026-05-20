"""First-time Fyers API app authorization helper.

When a user creates a new Fyers API app, they must authorize it once in a
browser before the automated TOTP login flow will work.  This module generates
the authorization URL and optionally opens it in the default browser.
"""

import webbrowser

from fyers_apiv3 import fyersModel

__all__ = ["setup_app"]

DEFAULT_REDIRECT_URI = (
    "https://trade.fyers.in/api-login/redirect-uri/index.html"
)


def setup_app(client_id, secret_key, redirect_uri=None, open_browser=True):
    """Generate and display the first-time authorization URL.

    This must be done **once** after creating a new Fyers API app.  After
    granting permissions in the browser, the automated login flow
    (``FyersAuth.get_token()``) will work without manual intervention.

    Args:
        client_id: Fyers API app client ID (e.g. ``"L9NY305RTW-100"``).
        secret_key: Fyers API app secret key.
        redirect_uri: Optional redirect URI.  Defaults to the standard
            Fyers redirect URI.
        open_browser: If ``True`` (default), automatically opens the
            authorization URL in the system's default browser.

    Returns:
        str: The authorization URL.

    Example::

        from fyers_auto_auth import setup_app

        url = setup_app(
            client_id="L9NY305RTW-100",
            secret_key="your_secret_key",
        )
    """
    if redirect_uri is None:
        redirect_uri = DEFAULT_REDIRECT_URI

    session = fyersModel.SessionModel(
        client_id=client_id,
        secret_key=secret_key,
        redirect_uri=redirect_uri,
        response_type="code",
        state="sample_state",
    )

    url = session.generate_authcode()

    # ── Pretty-print instructions ──────────────────────────────────────
    print()
    print("═" * 60)
    print("  FYERS API — FIRST-TIME APP SETUP")
    print("═" * 60)
    print()
    print("  1. Open this URL in your browser:")
    print(f"     {url}")
    print()
    print("  2. Login with your Fyers credentials and grant")
    print("     permissions to the app.")
    print()
    print("  3. You're done!  The automated token generation")
    print("     flow will work from now on.")
    print()
    print("═" * 60)
    print()

    if open_browser:
        webbrowser.open(url)

    return url
