import hashlib

def authenticate(password):
    password_hash = hashlib.md5(password.encode()).hexdigest()
    return password_hash
