from Crypto.Cipher import DES
import hashlib

def encrypt_data(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

def legacy_hash(data):
    return hashlib.sha1(data).hexdigest()
