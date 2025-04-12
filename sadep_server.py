import time
import base64
import json
import hashlib
import logging

from flask import Flask, request, jsonify
from service import Service


app = Flask(__name__)
service = Service.load_keys()

# Configure the logger
logging.basicConfig(
    filename='sadep_transaction_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

@app.route('/receive', methods=['POST'])
def receive_encrypted_payload():
    data = request.get_json()

    message = data.get("message")
    signature = data.get("signature")
    agent_pub_bytes = base64.b64decode(data.get("agent_public_key"))

    # Reconstruct Agent public key
    from cryptography.hazmat.primitives.asymmetric import ed25519
    agent_public_key = ed25519.Ed25519PublicKey.from_public_bytes(agent_pub_bytes)

    try:
        result = service.verify_and_decrypt(agent_public_key, message, signature)
        
        # Log key details
        nonce = message.get("nonce", "unknown_nonce")

        # Hash the payload for fingerprinting
        payload_str = json.dumps(result, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        # Get a short agent fingerprint (first 12 bytes of base64 pubkey)
        agent_fingerprint = base64.b64encode(agent_pub_bytes).decode()[:12]

        # Log transaction
        logging.info(f"Agent:{agent_fingerprint} | Nonce:{nonce} | PayloadHash:{payload_hash} | Status:Verified")


        # Prepare confirmation
        response = {
            "status": "success",
            "decrypted_payload": result,
            "service_confirmation": "Booking confirmed",
            "timestamp": int(time.time())
        }

        # SIGN THE CONFIRMATION HERE
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        response_bytes = json.dumps(response, sort_keys=True).encode("utf-8")
        signed_response = service.private_key.sign(
            response_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return jsonify({
            "response": response,
            "signature": base64.b64encode(signed_response).decode()
        })

    except Exception as e:
        # Don't sign errors — just return plain
        return jsonify({
            "status": "error",
            "error": str(e)
        })

    return jsonify(response)

if __name__ == '__main__':
    app.run(port=5000)
