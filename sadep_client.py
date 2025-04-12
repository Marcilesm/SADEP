import requests
import base64
import json
import time
from agent import Agent
from service import Service  # only for the service's public key

# Setup
agent = Agent()
service = Service.load_keys()  # This will match the Flask server's instance

payload = {
    "card_number": "4111 1111 1111 1111",
    "expiry": "12/26",
    "cvv": "123",
    "amount": "$1200",
    "purpose": "Flight booking"
}

message, signature = agent.encrypt_and_sign(service.public_key, payload)

data_to_send = {
    "message": message,
    "signature": signature,
    "agent_public_key": base64.b64encode(agent.public_key.public_bytes_raw()).decode()
}

# POST to Flask server
response = requests.post("http://localhost:5000/receive", json=data_to_send)

res = response.json()

# Extract and decode the response and signature
response_data = res["response"]
signature = base64.b64decode(res["signature"])

# Recreate the byte stream for signature verification
response_bytes = json.dumps(response_data, sort_keys=True).encode("utf-8")

# Verify the service's digital signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

try:
    service.public_key.verify(
        signature,
        response_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\n Signature verified: response came from the real service.")
except Exception as e:
    print(f"\n Invalid signature! Response may be tampered with: {e}")

# Display the response
print("\n Server Response:")
print(json.dumps(response.json(), indent=2))
