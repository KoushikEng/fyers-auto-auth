"""
Automated Fyers broker access token generation with encrypted storage.

This module handles the complete TOTP-based login flow:
    1. Send login OTP
    2. Verify OTP via TOTP
    3. Verify PIN
    4. Obtain authorization code
    5. Generate access token

Tokens are cached in memory and on disk (encrypted with Fernet).
A new token is generated only when the cached one is stale (not from today).
"""

from typing import Dict, Optional, Union
import asyncio
import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import struct
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from aiohttp import ClientSession
from cryptography.fernet import Fernet
from fyers_apiv3.fyersModel import SessionModel
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_random, RetryCallState

__all__ = ["FyersAuth"]

logger = logging.getLogger("fyers_auto_auth")
logger.setLevel(logging.DEBUG)

# ── Fyers API endpoints ────────────────────────────────────────────────
_BASE_URL = "https://api-t2.fyers.in/vagator/v2"
_BASE_URL_2 = "https://api-t1.fyers.in/api/v3"
_LOGIN_URL = _BASE_URL + "/send_login_otp_v2"
_VERIFY_OTP_URL = _BASE_URL + "/verify_otp"
_VERIFY_PIN_URL = _BASE_URL + "/verify_pin_v2"
_AUTH_CODE_URL = _BASE_URL_2 + "/token"
_VALIDATE_REFRESH_TOKEN_URL = _BASE_URL_2 + "/validate-refresh-token"

DEFAULT_REDIRECT_URI = (
    "https://trade.fyers.in/api-login/redirect-uri/index.html"
)
DEFAULT_TOKEN_DIR = Path.home() / ".fyers_auto_auth"
DEFAULT_TOKEN_FILE = DEFAULT_TOKEN_DIR / "tokens.json"

# ── Tenacity Callbacks ─────────────────────────────────────────────────
def _before_sleep_callback(retry_state: RetryCallState):
    """Callback executed before sleeping."""
    logger.warning(
        f"Retrying in {retry_state.next_action.sleep} seconds..."
    )

class FyersAuth:
    """Automated Fyers access-token manager.

    Generates, caches, and encrypts Fyers API access tokens.  Tokens are
    valid for one trading day; calling :meth:`get_token` on a new day
    triggers a fresh login flow automatically.

    Args:
        client_id (str): Fyers API app client ID (e.g. ``"L9NY305RTW-100"``).
        secret_key (str): Fyers API app secret key.
        username (str): Fyers account user ID.
        totp_key (str): Base-32 encoded TOTP secret key.
        pin (str): Fyers account PIN (numeric string).
        encryption_key (str | bytes): Fernet encryption key (``bytes`` or ``str``).
        token_file: Path where the encrypted token is stored.
            Accepts ``str`` or ``Path``; ``~`` is expanded.

            Resolution order:

            1. This explicit argument.
            2. ``FYERS_TOKEN_FILE`` environment variable.
            3. Default: ``~/.fyers_auto_auth/tokens.json``
        redirect_uri: Fyers redirect URI.  Defaults to the standard
            Fyers redirect URI.

    Example::

        from fyers_auto_auth import FyersAuth, load_fernet_key

        auth = FyersAuth(
            client_id="L9NY305RTW-100",
            secret_key="your_secret",
            username="DY12345",
            totp_key="BASE32TOTPKEY",
            pin="1234",
            encryption_key=load_fernet_key(),
        )

        access_token = auth.get_token()
    """

    def __init__(
        self,
        client_id: str,
        secret_key: str,
        username: str,
        totp_key: str,
        pin: str,
        encryption_key: Union[str, bytes],
        token_file: Union[str, Path, None] = None,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
    ):
        self.__client_id = client_id
        self.__secret_key = secret_key
        self.__username = username
        self.__totp_key = totp_key
        self.__pin = pin
        self.__redirect_uri = redirect_uri

        # Accept both str and bytes for the encryption key
        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode()
        self.__cipher_suite = Fernet(encryption_key)

        # Pre-compute encoded values
        self.__username_encoded = base64.b64encode(
            self.__username.encode()
        ).decode()
        self.__app_id_hash = self.__generate_app_id_hash()
        self.__pin_encoded = base64.b64encode(self.__pin.encode()).decode()
        self.__totp_decoded_key = base64.b32decode(
            self.__totp_key.upper()
            + "=" * ((8 - len(self.__totp_key)) % 8)
        )

        # Resolve token file path
        self.__token_file = self.__resolve_token_path(token_file)

        # In-memory cache
        self.__token = None
        self.__token_date = None

    # ── Token file path resolution ─────────────────────────────────────

    @staticmethod
    def __resolve_token_path(token_file: Union[str, Path, None] = None) -> Path:
        """Resolve the token file path from argument / env / default."""
        if token_file is not None:
            return Path(token_file).expanduser().resolve()

        env_path = os.environ.get("FYERS_TOKEN_FILE")
        if env_path:
            return Path(env_path).expanduser().resolve()

        return DEFAULT_TOKEN_FILE

    # ── TOTP generation ────────────────────────────────────────────────

    def __totp(self, key: bytes, time_step: int = 30, digits: int = 6, digest: str = "sha1") -> str:
        """Generate a TOTP token using the given key.

        If fewer than ``_TOTP_MIN_REMAINING`` seconds remain in the
        current time-step window, this method sleeps until the next
        window to avoid the code expiring before the server validates it.

        Args:
            key (bytes): The decoded TOTP secret.
            time_step (int): Time step in seconds.
            digits (int): Number of output digits.
            digest (str): HMAC digest algorithm.
        """
        # Guard against 30-second boundary race: if the current TOTP
        # code is about to expire, wait for the next window.
        _TOTP_MIN_REMAINING = 5  # seconds
        now = time.time()
        remaining = time_step - (now % time_step)
        if remaining < _TOTP_MIN_REMAINING:
            logger.debug(
                "TOTP window expires in %.1fs – waiting %.1fs for next window.",
                remaining,
                remaining,
            )
            time.sleep(remaining + 0.1)  # small buffer

        counter = struct.pack(">Q", int(time.time() / time_step))
        mac = hmac.new(key, counter, digest).digest()
        offset = mac[-1] & 0x0F
        binary = struct.unpack(">L", mac[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(binary)[-digits:].zfill(digits)

    # ── Encryption helpers ─────────────────────────────────────────────

    def __encrypt_token(self, token: str) -> str:
        return self.__cipher_suite.encrypt(token.encode()).decode()

    def __decrypt_token(self, encrypted_token: str) -> str:
        return self.__cipher_suite.decrypt(encrypted_token.encode()).decode()

    # ── Fyers login flow (async) ───────────────────────────────────────

    async def __send_login_otp(self, session: ClientSession) -> str:
        """Step 1: Request login OTP."""
        payload = json.dumps(
            {"fy_id": self.__username_encoded, "app_id": "2"}
        )
        async with session.post(_LOGIN_URL, data=payload) as response:
            if response.status != 200:
                raise Exception(
                    f"Error in step 1 OTP request: {await response.text()}"
                )
            return (await response.json())["request_key"]

    async def __verify_otp(self, session: ClientSession, request_key: str, totp: str) -> str:
        """Step 2: Verify OTP using TOTP."""
        payload = json.dumps(
            {"request_key": request_key, "otp": totp}
        )
        async with session.post(_VERIFY_OTP_URL, data=payload) as response:
            if response.status != 200:
                raise Exception(
                    f"Error in step 2 OTP verification: {await response.text()}"
                )
            return (await response.json())["request_key"]

    async def __verify_pin(self, session: ClientSession, request_key: str) -> str:
        """Step 3: Verify PIN."""
        payload = json.dumps({
            "request_key": request_key,
            "identity_type": "pin",
            "identifier": self.__pin_encoded,
        })
        async with session.post(_VERIFY_PIN_URL, data=payload) as response:
            if response.status != 200:
                raise Exception(
                    f"Error in step 3 PIN verification: {await response.text()}"
                )
            return (await response.json())["data"]["access_token"]

    async def __get_auth_code(self, session: ClientSession, bearer_token: str) -> str:
        """Step 4: Generate authorization code."""
        payload = json.dumps({
            "fyers_id": self.__username,
            "app_id": self.__client_id[:-4],
            "redirect_uri": self.__redirect_uri,
            "appType": self.__client_id[-3:],
            "code_challenge": "",
            "state": "abcdefg",
            "scope": "",
            "nonce": "",
            "response_type": "code",
            "create_cookie": True,
        })
        headers = {
            "authorization": f"Bearer {bearer_token}",
            "content-type": "application/json; charset=UTF-8",
        }
        async with session.post(
            _AUTH_CODE_URL, headers=headers, data=payload
        ) as response:
            if response.status != 308:
                raise Exception(
                    f"Error in step 4 token generation: {await response.text()}"
                )
            parsed = urlparse((await response.json())["Url"])
            return parse_qs(parsed.query)["auth_code"][0]

    async def __generate_tokens(self, auth_code: str) -> Dict[str, str]:
        """Step 5: Exchange authorization code for access token."""
        session = SessionModel(
            client_id=self.__client_id,
            secret_key=self.__secret_key,
            redirect_uri=self.__redirect_uri,
            response_type="code",
            grant_type="authorization_code",
        )
        session.set_token(auth_code)
        response = session.generate_token()

        if response.get("s") != "ok":
            raise Exception(f"Error generating tokens: {response}")

        return {
            "access_token": response["access_token"],
            "date": datetime.datetime.now().strftime("%Y-%m-%d"),
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_random(min=2, max=3),
        retry=retry_if_exception_type(Exception),
        before_sleep=_before_sleep_callback,
        reraise=True,
    )
    async def __get_all_tokens(self) -> Dict[str, str]:
        """Run the full async login pipeline and return token dict.

        Each step is awaited sequentially so that the TOTP is computed
        *after* step 1 completes, eliminating the 30-second boundary
        race that previously caused "invalid request" errors.
        """
        async with ClientSession() as s:
            request_key = await self.__send_login_otp(s)
            totp = self.__totp(self.__totp_decoded_key)
            request_key = await self.__verify_otp(s, request_key, totp)
            bearer_token = await self.__verify_pin(s, request_key)
            auth_code = await self.__get_auth_code(s, bearer_token)
            return await self.__generate_tokens(auth_code)

    def __get_all_tokens_sync(self) -> Dict[str, str]:
        """Synchronous wrapper around the async login pipeline."""
        return asyncio.run(self.__get_all_tokens())

    # ── Hashing ────────────────────────────────────────────────────────

    def __generate_app_id_hash(self) -> str:
        """Generate the SHA-256 hash of client_id:secret_key."""
        combined = f"{self.__client_id}:{self.__secret_key}"
        return hashlib.sha256(combined.encode()).hexdigest()

    # ── Token persistence ──────────────────────────────────────────────

    def __save_token(self, tokens: Dict[str, str]) -> None:
        """Save encrypted token and generation date to disk."""
        encrypted_tokens = {
            "access_token": self.__encrypt_token(tokens["access_token"]),
            "date": tokens["date"],
        }
        # Ensure parent directories exist
        self.__token_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.__token_file, "w") as f:
            json.dump(encrypted_tokens, f, indent=2)
        logger.debug("Token saved to %s", self.__token_file)

    def __load_token(self) -> Optional[Dict[str, str]]:
        """Load and decrypt token from disk.  Returns ``None`` on failure."""
        if not self.__token_file.exists():
            return None

        with open(self.__token_file, "r") as f:
            encrypted_token = json.load(f)

        if encrypted_token:
            try:
                return {
                    "access_token": self.__decrypt_token(
                        encrypted_token["access_token"]
                    ),
                    "date": encrypted_token["date"],
                }
            except Exception as e:
                logger.warning(
                    "Failed to decrypt existing token "
                    "(encryption key likely changed). "
                    "Ignoring old token.  Error: %s",
                    e,
                )

        return None

    # ── Public API ─────────────────────────────────────────────────────

    def get_token(self) -> str:
        """Obtain a valid Fyers access token for today.

        The method checks (in order):

        1. In-memory cache.
        2. Encrypted token file on disk.
        3. Fresh login flow via Fyers API.

        Tokens are considered valid for the calendar day they were
        generated.  A new token is fetched automatically when the
        cached one is from a previous day.

        Returns:
            str: The Fyers access token (e.g. ``"eyJ..."``).

        Raises:
            Exception: If the login flow fails after 3 retries.
        """
        today = datetime.date.today()

        # 1. In-memory cache
        if self.__token and self.__token_date == today:
            logger.debug("Returning in-memory cached token.")
            return self.__token

        # 2. Disk cache
        token = self.__load_token()
        if (
            token
            and today
            == datetime.datetime.strptime(token["date"], "%Y-%m-%d").date()
        ):
            self.__token = token["access_token"]
            self.__token_date = today
            logger.debug("Returning token loaded from disk.")
            return self.__token

        # 3. Fresh login
        logger.info("Generating a new access token via Fyers API...")
        token = self.__get_all_tokens_sync()
        self.__save_token(token)

        self.__token = token["access_token"]
        self.__token_date = today

        return self.__token

    def __call__(self) -> str:
        """Shorthand: ``auth()`` is equivalent to ``auth.get_token()``."""
        return self.get_token()


if __name__ == "__main__":
    from fyers_auto_auth import load_fernet_key
    from dotenv import load_dotenv
    import os
    
    load_dotenv()
    
    fyers = FyersAuth(
        client_id=os.getenv("CLIENT_ID"),
        secret_key=os.getenv("SECRET_KEY"),
        username=os.getenv("USERNAME"),
        totp_key=os.getenv("TOTP_KEY"),
        pin=os.getenv("PIN"),
        encryption_key=load_fernet_key(),
        token_file="tokens.json"
    )
    print(fyers.get_token())
