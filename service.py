import json
import base64
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


class Service:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()
        self.seen_nonces = set()

    def save_keys(self, private_key_path="service_private.pem", public_key_path="service_public.pem"):
        with open(private_key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(public_key_path, "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    @staticmethod
    def load_keys(private_key_path="service_private.pem", public_key_path="service_public.pem"):
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        service = Service.__new__(Service)  # Bypass __init__
        service.private_key = private_key
        service.public_key = public_key
        service.seen_nonces = set()
        return service

    def verify_and_decrypt(self, agent_public_key, message, b64_signature, allowed_drift=300):
        signature = base64.b64decode(b64_signature)
        message_bytes = json.dumps(message, sort_keys=True).encode("utf-8")

        # Verify signature
        agent_public_key.verify(signature, message_bytes)

        now = int(time.time())
        timestamp = message.get("timestamp", 0)
        nonce = message.get("nonce")

        if abs(now - timestamp) > allowed_drift:
            raise Exception(f" Timestamp out of range: {timestamp}")

        if nonce in self.seen_nonces:
            raise Exception(f" Replay detected: {nonce}")
        self.seen_nonces.add(nonce)

        encrypted_key = base64.b64decode(message["encrypted_key"])
        iv = base64.b64decode(message["iv"])
        ciphertext = base64.b64decode(message["ciphertext"])

        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_payload = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded_payload[-1]
        payload_bytes = padded_payload[:-pad_len]

        return json.loads(payload_bytes.decode("utf-8"))