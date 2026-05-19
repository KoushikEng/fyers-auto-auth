import asyncio
import datetime
import aiohttp
from cryptography.fernet import Fernet
import hashlib
from fyers_apiv3.fyersModel import SessionModel
import base64
import hmac
import struct
import time
from urllib.parse import urlparse, parse_qs
import os
import json
from tenacity import retry, stop_after_attempt, wait_random, retry_if_exception_type

ENCRYPTED_TOKENS_FILE = "secure_tokens.json"
REDIRECT_URI = "https://trade.fyers.in/api-login/redirect-uri/index.html"

BASE_URL = "https://api-t2.fyers.in/vagator/v2"
BASE_URL_2 = "https://api-t1.fyers.in/api/v3"
LOGIN_URL = BASE_URL + "/send_login_otp_v2"
VERIFY_OTP_URL = BASE_URL + "/verify_otp"
VERIFY_PIN_URL = BASE_URL + "/verify_pin_v2"
AUTH_CODE_URL = BASE_URL_2 + "/token"
VALIDATE_REFRESH_TOKEN_URL = BASE_URL_2 + "/validate-refresh-token"

class FyersToken:
    def __init__(self, totp_key, client_id, secret_key, pin, username, encryption_key, redirect_uri=REDIRECT_URI):
        """
        Initialize the FyersToken class with the required parameters.
        
        Args:
            totp_key (str): The TOTP key for the user.
            client_id (str): The client ID for the Fyers API.
            redirect_uri (str): The redirect URI for the Fyers API.
            secret_key (str): The secret key for the Fyers API.
            pin (str): The PIN for the user.
            username (str): The username for the Fyers account.
            encryption_key (str): The encryption key for encrypting and decrypting the tokens.
        """
        self.__totp_key = totp_key
        self.__client_id = client_id
        self.__redirect_uri = redirect_uri
        self.__secret_key = secret_key
        self.__pin = pin
        self.__username = username

        self.__cipher_suite = Fernet(encryption_key)
        self.__username_encoded = base64.b64encode(self.__username.encode()).decode()
        self.__app_id_hash = self.__generate_app_id_hash()
        self.__pin_encoded = base64.b64encode(self.__pin.encode()).decode() # cache encoded pin
        self.__totp_decoded_key = base64.b32decode(self.__totp_key.upper() + "=" * ((8 - len(self.__totp_key)) % 8)) # cache decoded TOTP key

        # Class variable to cache access token and generation date
        self.__token = None
        self.__token_date = None

    # Pass totp_decoded_key as an argument to avoid repeated decoding.
    def __totp(self, key, time_step=30, digits=6, digest="sha1"):
        """
        Generate a TOTP token using the given key.
        
        Args:
            key (bytes): The TOTP key.
            time_step (int): The time step for the TOTP token.
            digits (int): The number of digits in the TOTP token.
            digest (str): The digest algorithm to use for the TOTP token.
        """
        counter = struct.pack(">Q", int(time.time() / time_step))
        mac = hmac.new(key, counter, digest).digest()
        offset = mac[-1] & 0x0F
        binary = struct.unpack(">L", mac[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(binary)[-digits:].zfill(digits)

    def __encrypt_token(self, token):
        return self.__cipher_suite.encrypt(token.encode()).decode()

    def __decrypt_token(self, encryptedToken):
        return self.__cipher_suite.decrypt(encryptedToken.encode()).decode()

    async def __send_login_otp(self, session):
        # Step 1: Request login OTP
        data1 = f'{{"fy_id":"{self.__username_encoded}","app_id":"2"}}'
        async with session.post(LOGIN_URL, data=data1) as response:
            if response.status != 200:
                raise Exception(f"Error in step 1 OTP request: {await response.text()}")

            return (await response.json())["request_key"]

    async def __verify_otp(self, session, request_key, totp):
        # Step 2: Verify OTP using TOTP
        data2 = f'{{"request_key":"{await request_key}","otp":{totp}}}'
        async with session.post(VERIFY_OTP_URL, data=data2) as response:
            if response.status != 200:
                raise Exception(f"Error in step 2 OTP verification: {await response.text()}")
            return (await response.json())["request_key"]

    async def __verify_pin(self, session, request_key):
        """
        Verify the PIN using the Fyers API.
        
        Args:
            session (requests.Session): The requests session object.
            request_key (str): The request key for the user.
            
        Returns:
            str: The step 3 access token.
        """
        # Step 3: Verify PIN
        data3 = f'{{"request_key":"{await request_key}","identity_type":"pin","identifier":"{self.__pin_encoded}"}}'
        async with session.post(VERIFY_PIN_URL, data=data3) as response:
            if response.status != 200:
                raise Exception(f"Error in  step 3 PIN verification: {await response.text()}")
            return (await response.json())["data"]["access_token"]

    async def __get_auth_code(self, session, bearer_token):
        """
        Get the authorization code for generating the access token.
        
        Args:
            session (requests.Session): The requests session object.
            bearer_token (str): The bearer token for the user.
            
        Returns:
            str: The authorization code.
        """
        # Step 4: Generate authorization code
        data4 = f'{{"fyers_id":"{self.__username}","app_id":"{self.__client_id[:-4]}","redirect_uri":"{self.__redirect_uri}","appType":"100","code_challenge":"","state":"abcdefg","scope":"","nonce":"","response_type":"code","create_cookie":true}}'
        headers = {
            "authorization": f"Bearer {await bearer_token}",
            "content-type": "application/json; charset=UTF-8",
        }

        async with session.post(AUTH_CODE_URL, headers=headers, data=data4) as response:
            if response.status != 308:
                raise Exception(f"Error in step 4 token generation: {await response.text()}")

            # Extract authorization code from the redirect URL
            parsed = urlparse((await response.json())["Url"])
            return parse_qs(parsed.query)["auth_code"][0]

    async def __generate_tokens(self, auth_code):
        """
        Generate access and refresh tokens using the Fyers API.
        
        Args:
            auth_code (str): The authorization code.
            
        Returns:
            dict: A dictionary containing 'access_token', 'refresh_token', 'access_token_date', and 'refresh_token_date'.
        """
        session = SessionModel(client_id=self.__client_id, secret_key=self.__secret_key, redirect_uri=self.__redirect_uri, response_type="code", grant_type="authorization_code")
        session.set_token(await auth_code)
        response = session.generate_token()

        if response.get("s") != "ok":
            raise Exception(f"Error generating tokens: {response}")

        return {
            "access_token": response["access_token"],
            "date": datetime.datetime.now().strftime("%Y-%m-%d"),
        }

    async def __get_all_token(self):
        """
        Asynchronously generate access and refresh tokens using the Fyers API.
        
        Returns:
            dict: A dictionary containing 'access_token', 'refresh_token', and 'generation_date'.
        """
        async with aiohttp.ClientSession() as s:
            request_key = self.__send_login_otp(s)
            request_key = self.__verify_otp(s, request_key, self.__totp(self.__totp_decoded_key))
            bearer_token = self.__verify_pin(s, request_key)
            auth_code = self.__get_auth_code(s, bearer_token)
            tokens = self.__generate_tokens(auth_code)
            return await tokens
        
    def __get_all_token_async(self):
        return asyncio.run(self.__get_all_token())

    def __generate_app_id_hash(self):
        """Generate the app ID hash for the Fyers API."""
        combined = f"{self.__client_id}:{self.__secret_key}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def __save_token(self, tokens, file_path=ENCRYPTED_TOKENS_FILE):
        """Save encrypted token and generation date to a file."""
        encrypted_tokens = {
            "access_token": self.__encrypt_token(tokens["access_token"]),
            "date": tokens["date"],
        }
        with open(file_path, "w") as f:
            json.dump(encrypted_tokens, f, indent=2)

    def __load_token(self, file_path=ENCRYPTED_TOKENS_FILE):
        """Load encrypted token and generation date from a file."""
        if not os.path.exists(file_path):
            return None
        
        with open(file_path, "r") as f:
            encrypted_token = json.load(f)
        
        if encrypted_token:
            try:
                return {
                    "access_token": self.__decrypt_token(encrypted_token["access_token"]),
                    "date": encrypted_token["date"],
                }
            except Exception as e:
                print("[AUTH] Failed to decrypt the existing token "
                            "(encryption key likely changed). Ignoring old token. "
                            f"Error: {e}")

        return None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_random(min=2, max=3),
        retry=retry_if_exception_type(Exception),
        reraise=True
    )
    def get_token(self) -> str:
        """
        Get the access token for the Fyers API.
        
        Returns:
            str: The access token.
        """
        today = datetime.date.today()

        # first check if cached access token and generation date as class variable
        if self.__token and self.__token_date == today:
            return self.__token

        # check if token saved in file and not expired
        token = self.__load_token()
        if token and today == datetime.datetime.strptime(token["date"], "%Y-%m-%d").date():
            self.__token = token["access_token"]
            self.__token_date = today
            return self.__token

        else:
            # Get new tokens if no tokens found
            token = self.__get_all_token_async()
            self.__save_token(token)

        # cache access token and generation date as class variable
        self.__token = token["access_token"]
        self.__token_date = today

        return self.__token
    
    def __call__(self) -> str:
        """Get the access token for the Fyers API."""
        return self.get_token()

if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv()

    totp_key = os.getenv('TOTP_KEY')
    client_id = os.getenv('CLIENT_ID')
    redirect_uri = os.getenv('REDIRECT_URI')
    secret_key = os.getenv('SECRET_KEY')
    pin = os.getenv('PIN')
    username = os.getenv('USERNAME')
    try:
        with open("fernet_key.key", "rb") as f:
            ENCRYPTION_KEY = f.read()
    except FileNotFoundError:
        print("No encryption key found. Generate a new one using 'python generate_fernet_key.py'")
        raise SystemExit(1)
    
    t1 = time.time()
    fyersToken = FyersToken(totp_key, client_id, secret_key, pin, username, ENCRYPTION_KEY)
    print(fyersToken())
    t2 = time.time()

    print(f"Execution time: {t2-t1:.2f}s")

