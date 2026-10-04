from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

def encrypt(data, key):
    aes = AESGCM(key)
    return aes.encrypt(b"unique_nonce", data, None)

def hash_data(data):
    return hashlib.sha256(data).hexdigest()
