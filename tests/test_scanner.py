import os
import tempfile

from backend.scanner import scan_directory


def create_project(files):
    directory = tempfile.mkdtemp()

    for name, content in files.items():
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    return directory


def test_md5_detection():
    directory = create_project({
        "auth.py": "import hashlib\nhashlib.md5(b'test')\n"
    })

    findings = scan_directory(directory)

    assert any(
        f["rule_id"] == "CRYPTO-MD5"
        for f in findings
    )


def test_des_detection():
    directory = create_project({
        "legacy.py": "cipher = DES.new(key)\n"
    })

    findings = scan_directory(directory)

    assert any(
        f["rule_id"] == "CRYPTO-DES"
        for f in findings
    )


def test_sha1_detection():
    directory = create_project({
        "legacy.py": "hashlib.sha1(data)\n"
    })

    findings = scan_directory(directory)

    assert any(
        f["rule_id"] == "CRYPTO-SHA1"
        for f in findings
    )


def test_api_key_detection():
    directory = create_project({
        "config.py": 'API_KEY = "demo_key"\n'
    })

    findings = scan_directory(directory)

    assert any(
        f["rule_id"] == "SECRET-API-KEY"
        for f in findings
    )


def test_encryption_key_detection():
    directory = create_project({
        "config.py": 'ENCRYPTION_KEY = "demo_key"\n'
    })

    findings = scan_directory(directory)

    assert any(
        f["rule_id"] == "SECRET-ENCRYPTION-KEY"
        for f in findings
    )


def test_sha256_detection():
    directory = create_project({
        "crypto.py": "hashlib.sha256(data)\n"
    })

    findings = scan_directory(directory)

    assert any(
        f["rule_id"] == "CRYPTO-SHA256"
        for f in findings
    )


def test_ignored_directory():
    directory = create_project({
        "main.py": "print('safe')\n",
    })

    os.makedirs(os.path.join(directory, ".git"))

    with open(
        os.path.join(directory, ".git", "secret.py"),
        "w",
        encoding="utf-8",
    ) as f:
        f.write('API_KEY = "should_not_be_scanned"\n')

    findings = scan_directory(directory)

    assert not any(
        "should_not_be_scanned" in f.get("matched_text", "")
        for f in findings
    )


def test_multiple_findings():
    directory = create_project({
        "bad.py": """
import hashlib
hashlib.md5(data)
hashlib.sha1(data)
"""
    })

    findings = scan_directory(directory)

    rule_ids = {
        finding["rule_id"]
        for finding in findings
    }

    assert "CRYPTO-MD5" in rule_ids
    assert "CRYPTO-SHA1" in rule_ids
