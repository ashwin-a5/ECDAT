import ssl
import hashlib

SSL_PROTOCOL = "SSLv3"
TLS_PROTOCOL = "TLS1.0"

def create_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
