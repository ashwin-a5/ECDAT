RULE_DEFINITIONS = {
    "CRYPTO-MD5": {
        "title": "MD5 usage",
        "severity": "Critical",
        "category": "cryptography",
        "description": "MD5 is cryptographically broken and should not be used for security-sensitive hashing.",
        "recommendation": "Use a modern cryptographic hash such as SHA-256 or SHA-3 where appropriate.",
        "confidence": "High",
        "risk_score": 90,
    },

    "CRYPTO-SHA1": {
        "title": "SHA-1 usage",
        "severity": "High",
        "category": "cryptography",
        "description": "SHA-1 is deprecated for many security applications.",
        "recommendation": "Migrate to SHA-256 or SHA-3.",
        "confidence": "High",
        "risk_score": 75,
    },

    "CRYPTO-SHA256": {
        "title": "SHA-256 usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "SHA-256 is a modern cryptographic hash function.",
        "recommendation": "Continue using SHA-256 where a general-purpose cryptographic hash is appropriate.",
        "confidence": "High",
        "risk_score": 0,
    },

    "CRYPTO-SHA512": {
        "title": "SHA-512 usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "SHA-512 is a modern cryptographic hash function.",
        "recommendation": "Continue using SHA-512 where appropriate.",
        "confidence": "High",
        "risk_score": 0,
    },

    "CRYPTO-DES": {
        "title": "DES usage",
        "severity": "Critical",
        "category": "cryptography",
        "description": "DES is obsolete and does not provide adequate security.",
        "recommendation": "Replace DES with authenticated encryption such as AES-GCM.",
        "confidence": "High",
        "risk_score": 95,
    },

    "CRYPTO-3DES": {
        "title": "3DES usage",
        "severity": "High",
        "category": "cryptography",
        "description": "3DES is a legacy encryption algorithm that should be migrated away from.",
        "recommendation": "Replace 3DES with AES-based authenticated encryption.",
        "confidence": "High",
        "risk_score": 80,
    },

    "CRYPTO-RC4": {
        "title": "RC4 usage",
        "severity": "Critical",
        "category": "cryptography",
        "description": "RC4 has serious known cryptographic weaknesses.",
        "recommendation": "Remove RC4 and migrate to a modern authenticated encryption algorithm.",
        "confidence": "High",
        "risk_score": 95,
    },

    "CRYPTO-AES": {
        "title": "AES usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "AES is a modern symmetric encryption algorithm.",
        "recommendation": "Prefer authenticated modes such as AES-GCM and use secure key management.",
        "confidence": "High",
        "risk_score": 0,
    },

    "CRYPTO-RSA": {
        "title": "RSA usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "RSA can be secure when configured with appropriate key sizes and padding.",
        "recommendation": "Verify key size, padding, and implementation settings.",
        "confidence": "Medium",
        "risk_score": 0,
    },

    "CRYPTO-ECC": {
        "title": "ECC usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "Elliptic Curve Cryptography can provide strong security when modern curves and implementations are used.",
        "recommendation": "Verify that approved modern curves and implementations are used.",
        "confidence": "Medium",
        "risk_score": 0,
    },

    "CRYPTO-ECDSA": {
        "title": "ECDSA usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "ECDSA is a modern elliptic-curve signature algorithm.",
        "recommendation": "Verify curve selection, key management, and secure implementation.",
        "confidence": "Medium",
        "risk_score": 0,
    },

    "CRYPTO-ECDH": {
        "title": "ECDH usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "ECDH is used for elliptic-curve key agreement.",
        "recommendation": "Verify approved curves and secure key-management practices.",
        "confidence": "Medium",
        "risk_score": 0,
    },

    "CRYPTO-BCRYPT": {
        "title": "bcrypt usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "bcrypt is a password-hashing algorithm designed for password storage.",
        "recommendation": "Ensure appropriate cost parameters are configured.",
        "confidence": "High",
        "risk_score": 0,
    },

    "CRYPTO-SCRYPT": {
        "title": "scrypt usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "scrypt is a memory-hard password hashing algorithm.",
        "recommendation": "Ensure appropriate parameters are configured for the deployment environment.",
        "confidence": "High",
        "risk_score": 0,
    },

    "CRYPTO-ARGON2": {
        "title": "Argon2 usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "Argon2 is a modern password-hashing algorithm.",
        "recommendation": "Use appropriate memory, time, and parallelism parameters.",
        "confidence": "High",
        "risk_score": 0,
    },

    "CRYPTO-PBKDF2": {
        "title": "PBKDF2 usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "PBKDF2 is a password-based key derivation function.",
        "recommendation": "Use an appropriate iteration count and a modern underlying hash.",
        "confidence": "High",
        "risk_score": 0,
    },

    "CRYPTO-OPENSSL": {
        "title": "OpenSSL usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "OpenSSL provides cryptographic functionality; security depends on configuration and version.",
        "recommendation": "Use a supported OpenSSL version and secure protocol and cipher configuration.",
        "confidence": "Medium",
        "risk_score": 0,
    },

    "CRYPTO-SSL": {
        "title": "Legacy SSL protocol",
        "severity": "Critical",
        "category": "protocol",
        "description": "SSLv2 and SSLv3 are obsolete secure-communication protocols.",
        "recommendation": "Disable SSLv2/SSLv3 and use modern TLS configuration.",
        "confidence": "High",
        "risk_score": 95,
    },

    "CRYPTO-TLS": {
        "title": "TLS protocol usage",
        "severity": "Info",
        "category": "protocol",
        "description": "TLS is used for secure network communication; security depends on the protocol version and configuration.",
        "recommendation": "Prefer currently supported TLS versions and strong cipher suites.",
        "confidence": "Medium",
        "risk_score": 0,
    },

    "CRYPTO-CRYPTO-CIPHER": {
        "title": "Crypto.Cipher usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "A cryptographic cipher library is being used.",
        "recommendation": "Verify the selected algorithm, mode, nonce handling, and key management.",
        "confidence": "Medium",
        "risk_score": 0,
    },

    "CRYPTO-CIPHER": {
        "title": "Cipher API usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "A generic cipher API was detected.",
        "recommendation": "Review the selected cipher, mode, padding, and key-management configuration.",
        "confidence": "Low",
        "risk_score": 0,
    },

    "CRYPTO-HASHLIB": {
        "title": "Python hashlib usage",
        "severity": "Info",
        "category": "cryptography",
        "description": "The Python hashlib library is being used for cryptographic hashing.",
        "recommendation": "Review the selected hashing algorithm and ensure it is appropriate for the security requirement.",
        "confidence": "Medium",
        "risk_score": 0,
    },

    "SECRET-PASSWORD": {
        "title": "Hard-coded password",
        "severity": "High",
        "category": "secret",
        "description": "A password appears to be embedded directly in source code.",
        "recommendation": "Move credentials to a secure secret-management system.",
        "confidence": "High",
        "risk_score": 85,
    },

    "SECRET-PASSWD": {
        "title": "Hard-coded password",
        "severity": "High",
        "category": "secret",
        "description": "A password appears to be embedded directly in source code.",
        "recommendation": "Move credentials to a secure secret-management system.",
        "confidence": "High",
        "risk_score": 85,
    },

    "SECRET-SECRET": {
        "title": "Hard-coded secret",
        "severity": "High",
        "category": "secret",
        "description": "A hard-coded secret appears to be present in source code.",
        "recommendation": "Remove the secret from source code and use secure secret management.",
        "confidence": "High",
        "risk_score": 85,
    },

    "SECRET-API-KEY": {
        "title": "Hard-coded API key",
        "severity": "Critical",
        "category": "secret",
        "description": "An API key appears to be embedded directly in source code.",
        "recommendation": "Remove and rotate the key, then use secure secret management.",
        "confidence": "High",
        "risk_score": 95,
    },

    "SECRET-ENCRYPTION-KEY": {
        "title": "Hard-coded encryption key",
        "severity": "Critical",
        "category": "secret",
        "description": "An encryption key appears to be embedded directly in source code.",
        "recommendation": "Rotate the key and store cryptographic keys using secure key management.",
        "confidence": "High",
        "risk_score": 100,
    },

    "SECRET-PRIVATE-KEY": {
        "title": "Private key detected",
        "severity": "Critical",
        "category": "secret",
        "description": "A private cryptographic key appears to be present in source code.",
        "recommendation": "Remove the key from source control, rotate it, and use secure key management.",
        "confidence": "High",
        "risk_score": 100,
    },
}


def get_rule(rule_id: str) -> dict:
    """Return metadata for a rule."""

    return RULE_DEFINITIONS.get(
        rule_id,
        {
            "title": "Unknown finding",
            "severity": "Info",
            "category": "unknown",
            "description": "No rule metadata is available.",
            "recommendation": "Review this finding manually.",
            "confidence": "Low",
            "risk_score": 0,
        },
    )
