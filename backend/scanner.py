"""ECDAT Source Code Cryptographic Discovery and Secret Scanner."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Pattern, Set


TARGET_EXTENSIONS: Set[str] = {
    ".py",
    ".js",
    ".ts",
    ".java",
    ".go",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".php",
    ".rb",
    ".rs",
    ".swift",
    ".kt",
    ".kts",
    ".xml",
    ".json",
    ".yaml",
    ".yml",
    ".conf",
    ".cfg",
    ".ini",
    ".properties",
}


IGNORED_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
}


MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


CRYPTO_RULES: List[Dict[str, Any]] = [

    {
        "rule_id": "CRYPTO-MD5",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bMD5\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-SHA1",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bSHA-?1\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-SHA256",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bSHA-?256\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-SHA512",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bSHA-?512\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-3DES",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(
            r"\b(?:3DES|Triple[\s_-]?DES)\b",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "CRYPTO-DES",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(
            r"(?<![A-Za-z0-9])DES(?![A-Za-z0-9])",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "CRYPTO-RC4",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bRC4\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-AES",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(
            r"\bAES(?:-?(?:128|192|256))?\b",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "CRYPTO-RSA",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bRSA\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-ECC",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bECC\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-ECDSA",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bECDSA\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-ECDH",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bECDH\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-BCRYPT",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bbcrypt\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-SCRYPT",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bscrypt\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-ARGON2",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(
            r"\bArgon2(?:i|d|id)?\b",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "CRYPTO-PBKDF2",
        "category": "cryptography",
        "detection_type": "Algorithm",
        "pattern": re.compile(r"\bPBKDF2\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-OPENSSL",
        "category": "cryptography",
        "detection_type": "API / Library",
        "pattern": re.compile(r"\bOpenSSL\b", re.IGNORECASE),
    },

    {
        "rule_id": "CRYPTO-CRYPTO-CIPHER",
        "category": "cryptography",
        "detection_type": "API / Library",
        "pattern": re.compile(
            r"\bCrypto\.Cipher\b",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "CRYPTO-CIPHER",
        "category": "cryptography",
        "detection_type": "API / Library",
        "pattern": re.compile(
            r"\bCipher\b",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "CRYPTO-HASHLIB",
        "category": "cryptography",
        "detection_type": "API / Library",
        "pattern": re.compile(
            r"\bhashlib\b",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "CRYPTO-SSL",
        "category": "protocol",
        "detection_type": "Protocol",
        "pattern": re.compile(
            r"\bSSLv(?:2|3)\b",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "CRYPTO-TLS",
        "category": "protocol",
        "detection_type": "Protocol",
        "pattern": re.compile(
            r"\bTLS(?:v?(?:1(?:\.[0-3])?|13))\b",
            re.IGNORECASE,
        ),
    },
]


SECRET_RULES: List[Dict[str, Any]] = [

    {
        "rule_id": "SECRET-PASSWORD",
        "category": "secret",
        "detection_type": "Secret",
        "pattern": re.compile(
            r"\bpassword\s*[:=]\s*[\"'][^\"'\r\n]+[\"']",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "SECRET-PASSWD",
        "category": "secret",
        "detection_type": "Secret",
        "pattern": re.compile(
            r"\bpasswd\s*[:=]\s*[\"'][^\"'\r\n]+[\"']",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "SECRET-SECRET",
        "category": "secret",
        "detection_type": "Secret",
        "pattern": re.compile(
            r"\bsecret\s*[:=]\s*[\"'][^\"'\r\n]+[\"']",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "SECRET-API-KEY",
        "category": "secret",
        "detection_type": "Secret",
        "pattern": re.compile(
            r"\bapi_key\s*[:=]\s*[\"'][^\"'\r\n]+[\"']",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "SECRET-ENCRYPTION-KEY",
        "category": "secret",
        "detection_type": "Secret",
        "pattern": re.compile(
            r"\bencryption_key\s*[:=]\s*[\"'][^\"'\r\n]+[\"']",
            re.IGNORECASE,
        ),
    },

    {
        "rule_id": "SECRET-PRIVATE-KEY",
        "category": "secret",
        "detection_type": "Secret",
        "pattern": re.compile(
            r"(?:"
            r"\bprivate_key\s*[:=]\s*[\"'][^\"'\r\n]+[\"']"
            r"|"
            r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"
            r")",
            re.IGNORECASE,
        ),
    },
]


ALL_RULES: List[Dict[str, Any]] = (
    CRYPTO_RULES + SECRET_RULES
)


def is_binary_file(file_path: str) -> bool:
    """Return True if a file appears to be binary."""

    try:
        with open(file_path, "rb") as f:
            return b"\0" in f.read(1024)

    except OSError:
        return True


def is_import_line(line: str) -> bool:
    """Return True if the line primarily represents an import."""

    stripped = line.strip().lower()

    return (
        stripped.startswith("import ")
        or stripped.startswith("from ")
        or stripped.startswith("using ")
        or stripped.startswith("#include")
        or stripped.startswith("require(")
    )


def should_skip_rule_on_import(
    rule: Dict[str, Any],
    line: str,
) -> bool:
    """Suppress import-only references."""

    if not is_import_line(line):
        return False

    detection_type = rule.get("detection_type")
    rule_id = rule.get("rule_id")

    if detection_type == "Algorithm":
        return True

    if rule_id in {
        "CRYPTO-CIPHER",
        "CRYPTO-CRYPTO-CIPHER",
        "CRYPTO-HASHLIB",
        "CRYPTO-OPENSSL",
        "CRYPTO-SSL",
        "CRYPTO-TLS",
    }:
        return True

    return False


def get_line_confidence(
    rule: Dict[str, Any],
    line: str,
) -> str:
    """Estimate detection confidence."""

    detection_type = rule.get(
        "detection_type"
    )

    if detection_type == "Secret":
        return "High"

    if detection_type == "Algorithm":
        return "High"

    if detection_type == "Protocol":

        if re.search(
            r"SSLv[23]|TLS\s*1\.0|TLS\s*1\.1|TLS1\.0|TLS1\.1",
            line,
            re.IGNORECASE,
        ):
            return "High"

        return "Medium"

    return "Medium"


def scan_file(file_path: str) -> list[dict]:
    """Scan one source file."""

    findings: list[dict] = []

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="strict",
        ) as f:

            for line_no, line in enumerate(
                f,
                start=1,
            ):

                for rule in ALL_RULES:

                    if should_skip_rule_on_import(
                        rule,
                        line,
                    ):
                        continue

                    pattern: Pattern[str] = rule["pattern"]

                    # Only keep the first match of a particular
                    # rule on a source line.
                    match = pattern.search(line)

                    if not match:
                        continue

                    findings.append(
                        {
                            "file": file_path,
                            "line": line_no,
                            "matched_text": match.group(0),
                            "rule_id": rule["rule_id"],
                            "category": rule["category"],
                            "detection_type": rule[
                                "detection_type"
                            ],
                            "confidence": get_line_confidence(
                                rule,
                                line,
                            ),
                            "severity": None,
                            "recommendation": None,
                        }
                    )

    except (
        UnicodeDecodeError,
        OSError,
    ):
        pass

    return findings


def scan_directory(
    directory: str,
) -> list[dict]:
    """Recursively scan a directory."""

    findings: list[dict] = []

    if not os.path.isdir(directory):
        return findings

    for root, dirs, files in os.walk(directory):

        dirs[:] = [
            d
            for d in dirs
            if d not in IGNORED_DIRS
        ]

        for file_name in sorted(files):

            _, ext = os.path.splitext(
                file_name
            )

            if ext.lower() not in TARGET_EXTENSIONS:
                continue

            file_path = os.path.join(
                root,
                file_name
            )

            try:

                if (
                    os.path.getsize(file_path)
                    > MAX_FILE_SIZE_BYTES
                ):
                    continue

            except OSError:
                continue

            if is_binary_file(file_path):
                continue

            findings.extend(
                scan_file(file_path)
            )

    return findings


def count_scannable_files(
    directory: str,
) -> int:
    """Count files ECDAT can analyze."""

    count = 0

    if not os.path.isdir(directory):
        return 0

    for root, dirs, files in os.walk(directory):

        dirs[:] = [
            d
            for d in dirs
            if d not in IGNORED_DIRS
        ]

        for file_name in files:

            _, ext = os.path.splitext(
                file_name
            )

            if ext.lower() not in TARGET_EXTENSIONS:
                continue

            file_path = os.path.join(
                root,
                file_name
            )

            try:

                if (
                    os.path.getsize(file_path)
                    > MAX_FILE_SIZE_BYTES
                ):
                    continue

            except OSError:
                continue

            if not is_binary_file(file_path):
                count += 1

    return count


if __name__ == "__main__":

    import json
    import sys

    target_dir = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "."
    )

    results = scan_directory(
        target_dir
    )

    print(
        json.dumps(
            results,
            indent=2
        )
    )
