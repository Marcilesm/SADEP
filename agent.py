import os
import json
import base64
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class Agent:
    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def encrypt_and_sign(self, service_public_key, payload_dict):
        payload_bytes = json.dumps(payload_dict).encode("utf-8")

        aes_key = os.urandom(32)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        pad_len = 16 - len(payload_bytes) % 16
        padded = payload_bytes + bytes([pad_len]) * pad_len
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        encrypted_key = service_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        message = {
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "timestamp": int(time.time()),
            "nonce": str(uuid.uuid4())
        }

        signature = self.private_key.sign(json.dumps(message, sort_keys=True).encode("utf-8"))
        return message, base64.b64encode(signature).decode()