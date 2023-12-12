import hashlib
import cryptography.fernet
import base64

class HashLineage(cryptography.fernet.Fernet):
    def __init__(self, seed: bytes):
        seed = hashlib.sha256(seed).digest()
        seed = base64.urlsafe_b64encode(seed)
        print(f"Final seed: {seed}")
        super().__init__(seed)

    def _encrypt_from_parts(self, data, time, iv):
        return cryptography.fernet.Fernet._encrypt_from_parts(self, data, 0, b'0' * 16)

