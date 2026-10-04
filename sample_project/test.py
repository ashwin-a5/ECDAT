import hashlib

password_hash = hashlib.md5(password.encode()).hexdigest()
