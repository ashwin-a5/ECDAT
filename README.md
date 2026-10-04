# ECDAT
## Enterprise Cryptographic Discovery & Analysis Tool

ECDAT is a lightweight static-analysis tool for discovering cryptographic algorithms, security-sensitive APIs, legacy protocols, and hard-coded secrets in source code.

The project provides a web dashboard for scanning a directory, analyzing findings, calculating risk, storing scan history, and exporting JSON reports.

---

## Features

- Static source-code scanning
- Cryptographic algorithm detection
- Weak/legacy algorithm detection
- TLS/SSL protocol detection
- Cryptographic API/library detection
- Hard-coded secret detection
- Severity classification
- Risk scoring
- Finding consolidation and deduplication
- SQLite scan history
- REST API
- Web-based security dashboard
- Finding search and filtering
- JSON report export

---

## Architecture

```text
Source Code
     |
     v
+-----------+
|  Scanner  |
+-----------+
     |
     v
+----------------+
|    Analyzer    |
|  Risk Rules    |
+----------------+
     |
     v
+-----------+
|  SQLite   |
| Database  |
+-----------+
     |
     v
+-----------+
| FastAPI   |
| REST API  |
+-----------+
     |
     v
+----------------+
| Web Dashboard  |
+----------------+
