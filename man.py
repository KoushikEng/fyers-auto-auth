"""
First time user of fyers API? Follow the steps below to generate your access token
and start using the API. After it, you can use automated scripts to generate access token
and use the API without manual intervention.
"""

from fyers_apiv3 import fyersModel
from dotenv import load_dotenv
import os

load_dotenv()

# Replace these values with your actual API credentials
client_id = os.getenv('CLIENT_ID')
secret_key = os.getenv('SECRET_KEY')
redirect_uri = "https://trade.fyers.in/api-login/redirect-uri/index.html"
response_type = "code"
state = "sample_state"

# Create a session model with the provided credentials
session = fyersModel.SessionModel(
    client_id=client_id,
    secret_key=secret_key,
    redirect_uri=redirect_uri,
    response_type=response_type
)

# Generate the auth code using the session model
response = session.generate_authcode()

# Print the auth code received in the response
print(response)


