# fyers-auto-auth

Automated [Fyers](https://fyers.in/) broker access token generation with encrypted storage.

Handles the complete TOTP-based login flow, generates access tokens, and caches them encrypted on disk — refreshing automatically each day. Built for use in automated trading systems.

## Features

- **Fully automated** — no manual browser login needed (after one-time setup)
- **Encrypted storage** — access tokens are encrypted at rest using [Fernet](https://cryptography.io/en/latest/fernet/) symmetric encryption
- **Smart caching** — tokens are cached in memory and on disk; a new token is fetched only when the cached one is stale
- **Configurable paths** — choose where to store your encrypted tokens and encryption keys
- **CLI tools** — generate encryption keys and perform first-time app setup from the terminal
- **Retry logic** — automatic retries with jitter on transient failures

## Installation

```bash
pip install fyers-auto-auth
```

## Prerequisites

You need a **Fyers API app**. If you don't have one:

1. Go to [Fyers API Dashboard](https://myapi.fyers.in/dashboard) and create a new app.
2. Note down your **Client ID**, **Secret Key**, and **Redirect URI**.
3. Enable TOTP on your Fyers account and save the **TOTP secret key**.

## Quick Start

### 1. First-Time App Setup (one-time only)

When you create a new Fyers API app, you must authorize it once in a browser:

```bash
fyers-auto-auth setup-app --client-id "XXXXXXXXXX-100" --secret-key "your_secret_key"
```

This opens a URL in your browser — log in and grant permissions. This is a **one-time** step.

Or programmatically:

```python
from fyers_auto_auth import setup_app

setup_app(client_id="XXXXXXXXXX-100", secret_key="your_secret_key")
```

### 2. Generate an Encryption Key

```bash
fyers-auto-auth generate-key
# Key saved to: ~/.fyers_auto_auth/fernet.key
```

Or with a custom path:

```bash
fyers-auto-auth generate-key --output /path/to/my_key.key
```

Or programmatically:

```python
from fyers_auto_auth import generate_fernet_key

key = generate_fernet_key(save_to="~/.fyers_auto_auth/fernet.key")
```

### 3. Get Access Tokens

```python
from fyers_auto_auth import FyersAuth, load_fernet_key

auth = FyersAuth(
    client_id="XXXXXXXXXX-100",
    secret_key="your_secret_key",
    username="your_fyers_id",
    totp_key="YOUR_TOTP_BASE32_KEY",
    pin="1234",
    encryption_key=load_fernet_key(),
)

# Get token — cached, auto-refreshes daily
access_token = auth.get_token()

# Or use the shorthand
access_token = auth()
```

### 4. Use with Fyers API

```python
from fyers_apiv3 import fyersModel
from fyers_auto_auth import FyersAuth, load_fernet_key

auth = FyersAuth(
    client_id="XXXXXXXXXX-100",
    secret_key="your_secret_key",
    username="your_fyers_id",
    totp_key="YOUR_TOTP_BASE32_KEY",
    pin="1234",
    encryption_key=load_fernet_key(),
)

fyers = fyersModel.FyersModel(
    client_id="XXXXXXXXXX-100",
    token=auth.get_token(),
    is_async=False,
    log_path="",
)

print(fyers.get_profile())
```

## Configuration

### Token File Location

By default, encrypted tokens are stored at `~/.fyers_auto_auth/tokens.json`.

You can customize this:

```python
# Option 1: Pass directly
auth = FyersAuth(..., token_file="/path/to/my_tokens.json")

# Option 2: Environment variable
# export FYERS_TOKEN_FILE=/path/to/my_tokens.json
auth = FyersAuth(...)  # picks up from env automatically
```

**Resolution order:** explicit argument → `FYERS_TOKEN_FILE` env var → default path.

### Encryption Key Location

The `load_fernet_key()` helper looks for the key in this order:

1. Explicit `path` argument: `load_fernet_key("/path/to/key.key")`
2. `FYERS_FERNET_KEY` env var (the raw key value)
3. `FYERS_FERNET_KEY_FILE` env var (path to a key file)
4. Default: `~/.fyers_auto_auth/fernet.key`

### Environment Variables

| Variable | Description |
|----------|-------------|
| `FYERS_TOKEN_FILE` | Path to the encrypted token file |
| `FYERS_FERNET_KEY` | Fernet key value (raw) |
| `FYERS_FERNET_KEY_FILE` | Path to a file containing the Fernet key |

## CLI Reference

```
fyers-auto-auth generate-key [--output PATH]
    Generate a new Fernet encryption key.

fyers-auto-auth setup-app --client-id ID --secret-key KEY [--redirect-uri URI] [--no-browser]
    First-time Fyers API app authorization.
```

## API Reference

### `FyersAuth(client_id, secret_key, username, totp_key, pin, encryption_key, token_file=None, redirect_uri=None)`

Main class for automated token management.

- **`get_token()`** → `str` — Get a valid access token (auto-refreshes if stale).
- **`auth()`** → `str` — Shorthand for `get_token()`.

### `generate_fernet_key(save_to=None)` → `bytes`

Generate a new Fernet encryption key. Optionally save to a file.

### `load_fernet_key(path=None)` → `bytes`

Load a Fernet key from file or environment variable.

### `setup_app(client_id, secret_key, redirect_uri=None, open_browser=True)` → `str`

Generate and display the first-time authorization URL.

## How It Works

```
get_token() called
     │
     ├─ Check in-memory cache → return if today's token
     │
     ├─ Check encrypted file on disk → decrypt & return if today's token
     │
     └─ Run full login flow:
         1. Send login OTP request
         2. Verify OTP using TOTP (generated from your secret key)
         3. Verify PIN
         4. Get authorization code
         5. Exchange auth code for access token
         6. Encrypt & save to disk
         7. Cache in memory & return
```

## Security Notes

- **Never commit** your `.env` files, `.key` files, or `tokens.json` to version control.
- Add these to your `.gitignore`:
  ```
  *.env
  *.key
  tokens.json
  ```
- The Fernet encryption key is the master secret — treat it like a password.
- Tokens are valid for one trading day only.

## License

[MIT](LICENSE)
