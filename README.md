# SecureChat - Secure Console-Based Chat System

**A cryptographically secure chat system implementing Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR) using AES-128, RSA-2048, Diffie-Hellman, and X.509 certificates.**

**GitHub Repository:** https://github.com/naqvihassan/securechat-skeleton

**Student:** Hassan Naqvi  
**Roll Number:** 22I-0797  
**Course:** CS-3002 Information Security - Fall 2025  
**Institution:** FAST-NUCES

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Sample Input/Output](#sample-inputoutput)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Security Features](#security-features)
- [Troubleshooting](#troubleshooting)
- [Project Status](#project-status)

---

## Overview

This is the complete implementation of Assignment #2 for CS-3002 Information Security, demonstrating practical application of cryptographic primitives to build a secure communication system.

### What This System Does

- Establishes secure client-server chat using **custom PKI** (no TLS/SSL)
- Implements **mutual authentication** via X.509 certificates
- Encrypts all communication with **AES-128** and **Diffie-Hellman** key exchange
- Ensures **message integrity** with RSA digital signatures
- Provides **non-repudiation** through signed session transcripts

### Implementation Highlights

- Complete implementation of all cryptographic modules
- Working client-server chat application with encrypted messaging
- Certificate generation scripts (CA + server + client)
- MySQL-backed user authentication with salted password hashing
- Comprehensive security testing and validation with evidence
- Full non-repudiation support with signed session receipts

---

## Features

### Security Properties (CIANR)

- **Confidentiality:** AES-128 CBC encryption with random IVs
- **Integrity:** SHA-256 message digests detect tampering
- **Authenticity:** RSA-2048 digital signatures prove sender identity
- **Non-Repudiation:** Signed transcripts provide cryptographic proof

### Implemented Components

- Self-signed Root CA with certificate issuance
- Mutual certificate-based authentication
- Diffie-Hellman key exchange (2048-bit safe prime)
- Secure credential storage with unique salts per user
- Replay attack prevention via sequence numbers
- Session transcripts with cryptographic receipts
- Encrypted message exchange with per-message signatures

---

## System Requirements

### Software Dependencies

- **Python:** 3.9 or higher
- **Database:** MySQL 8.0 or MariaDB 10.x
- **OS:** Linux (Kali/Ubuntu recommended), macOS, or Windows with WSL

### Python Libraries

```
cryptography==41.0.7
pycryptodome==3.19.0
mysql-connector-python==8.2.0
python-dotenv==1.0.0
```

### Optional Tools

- OpenSSL (certificate inspection)
- Wireshark (network traffic analysis)
- Git (version control)

---

## Installation & Setup

### Step 1: Clone Repository

```bash
git clone https://github.com/naqvihassan/securechat-skeleton.git
cd securechat-skeleton
```

### Step 2: Create Virtual Environment

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate     # Windows
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Setup MySQL Database

#### Start MySQL Service

```bash
# Linux
sudo systemctl start mysql

# macOS
brew services start mysql
```

#### Create Database and User

Login to MySQL:

```bash
sudo mysql -u root -p
# OR
mysql -u root -p
```

Inside MySQL prompt, execute:

```sql
-- Create database
CREATE DATABASE securechat;

-- Create application user
CREATE USER 'chatuser'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON securechat.* TO 'chatuser'@'localhost';
FLUSH PRIVILEGES;

-- Switch to database
USE securechat;

-- Create users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_username (username)
);

-- Verify table creation
DESCRIBE users;

-- Exit MySQL
EXIT;
```

### Step 5: Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Edit with your settings
nano .env
```

Update `.env` with your database credentials:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=chatuser
DB_PASSWORD=your_secure_password
DB_NAME=securechat

SERVER_HOST=127.0.0.1
SERVER_PORT=9999
```

### Step 6: Generate PKI Certificates

```bash
# Generate Root CA
python3 scripts/gen_ca.py

# Generate Server Certificate
python3 scripts/gen_cert.py server

# Generate Client Certificate
python3 scripts/gen_cert.py client
```

**Expected Output:**

```
[*] Generating RSA private key for Root CA...
[*] Creating self-signed root certificate...
[✓] Root CA generated successfully!
    Private Key: certs/ca_private.key
    Certificate: certs/ca_cert.pem

[*] Loading CA private key and certificate...
[*] Generating RSA private key for server...
[✓] Server certificate generated successfully!
    Private Key: certs/server_private.key
    Certificate: certs/server_cert.pem

[*] Loading CA private key and certificate...
[*] Generating RSA private key for client...
[✓] Client certificate generated successfully!
    Private Key: certs/client_private.key
    Certificate: certs/client_cert.pem
```

#### Verify Certificates (Optional)

```bash
# Inspect CA certificate
openssl x509 -in certs/ca_cert.pem -text -noout

# Verify certificate chain
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem
```

**Expected Output:** Both should show `OK`

---

## Configuration

### Required Configuration Files

#### Environment Variables (.env)

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=chatuser
DB_PASSWORD=your_secure_password
DB_NAME=securechat

# Server Configuration
SERVER_HOST=127.0.0.1
SERVER_PORT=9999
```

#### Git Ignore (.gitignore)

**CRITICAL:** Never commit secrets to Git!

```gitignore
# Secrets - NEVER COMMIT
certs/
*.key
*.pem
.env

# Transcripts
transcripts/
*.log

# Python
venv/
__pycache__/
*.pyc

# Database
*.sql

# IDE
.vscode/
.idea/
```

### Network Configuration

**For localhost testing (default):**
- Server listens on `127.0.0.1:9999`
- Client connects to `127.0.0.1:9999`

**For network testing (optional):**

```env
# Server .env
SERVER_HOST=0.0.0.0  # Listen on all interfaces

# Client .env  
SERVER_HOST=192.168.1.100  # Server's actual IP
```

---

## Usage

### Running the Application

#### Terminal 1: Start Server

```bash
cd securechat-skeleton
source venv/bin/activate
python3 -m app.server
```

**Server Output:**

```
============================================================
   SECURE CHAT SERVER - Control Plane
============================================================
[*] Loading server certificate and private key...
[*] Loading CA certificate...
[✓] Server initialized successfully

[✓] Server listening on 127.0.0.1:9999
[*] Waiting for client connection...
```

#### Terminal 2: Start Client

```bash
cd securechat-skeleton
source venv/bin/activate
python3 -m app.client
```

**Client Output:**

```
============================================================
   SECURE CHAT CLIENT - Control Plane
============================================================

[*] Loading client certificate and private key...
[*] Loading CA certificate...
[✓] Client initialized successfully

[*] Connecting to 127.0.0.1:9999...
[✓] Connected to server

[*] Starting certificate exchange...
[*] Received server certificate
[✓] Server certificate verified: Certificate valid
[✓] Certificate exchange completed

[*] Starting control plane DH key exchange...
[✓] Control plane key established

============================================================
Choose: (1) Register  (2) Login: 
```

---

## Sample Input/Output

### Scenario 1: User Registration

**Client Input:**

```
Choose: (1) Register  (2) Login: 1
============================================================
   USER REGISTRATION
============================================================
Email: hassan@example.com
Username: hassan_test
Password: secure123
```

**Client Output:**

```
[✓] Registration successful
```

**Server Output:**

```
[+] Client connected from ('127.0.0.1', 54321)
[*] Starting certificate exchange...
[*] Received client certificate
[✓] Client certificate verified: Certificate valid
[✓] Certificate exchange completed successfully
[*] Starting control plane DH key exchange...
[*] Received client DH public key
[✓] Control plane key established
[*] Waiting for authentication request...
[*] Processing registration request...
[✓] User registered: hassan_test (hassan@example.com)
```

**Database Verification:**

```bash
mysql -u chatuser -p securechat -e "SELECT id, email, username, created_at FROM users;"
```

**Output:**

```
+----+----------------------+--------------+---------------------+
| id | email                | username     | created_at          |
+----+----------------------+--------------+---------------------+
|  1 | hassan@example.com   | hassan_test  | 2025-11-17 20:30:45 |
+----+----------------------+--------------+---------------------+
```

### Scenario 2: User Login

**Client Input:**

```
Choose: (1) Register  (2) Login: 2
============================================================
   USER LOGIN
============================================================
Email: hassan@example.com
Password: secure123
```

**Client Output:**

```
[✓] Login successful! Welcome, hassan_test

[*] Ready for chat session...
```

**Server Output:**

```
[*] Processing login request...
[✓] User logged in: hassan_test (hassan@example.com)
[*] Ready for session key exchange...
```

### Scenario 3: Encrypted Chat Session

**After successful login, encrypted messages are exchanged:**

**Client sends:**

```
Message: Hello from secure chat!
[✓] Message sent (seqno: 1)
```

**Server receives:**

```
[✓] Message received from hassan_test: Hello from secure chat!
```

**Message format on wire (JSON):**

```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1700000000000,
  "ct": "aGVsbG8gZnJvbSBzZWN1cmUgY2hhdCE=",
  "sig": "VvOwiEsCjdC4atmq3zqVYmk9CZ8..."
}
```

**Note:** The `ct` field contains base64-encoded AES ciphertext. Plaintext is never transmitted.

### Scenario 4: Invalid Login

**Client Input:**

```
Email: hassan@example.com
Password: wrongpassword
```

**Client Output:**

```
[✗] Login failed: Invalid credentials
```

**Server Output:**

```
[*] Processing login request...
[✗] Login failed: incorrect password for hassan@example.com
```

---

## Testing

### Functional Tests

#### Test 1: Certificate Validation

```bash
# Verify certificate chain
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem
```

**Expected:**

```
certs/server_cert.pem: OK
certs/client_cert.pem: OK
```

#### Test 2: Database Operations

```bash
# Test database connection
python3 << 'EOF'
from app.storage.db import get_connection
conn = get_connection()
if conn:
    print("✓ Database connection successful")
    conn.close()
else:
    print("✗ Connection failed")
EOF
```

#### Test 3: Crypto Modules

```bash
# Test all cryptographic functions
python3 << 'EOF'
from app.crypto.pki import load_certificate, verify_certificate
from app.crypto.dh import generate_dh_parameters, derive_aes_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import rsa_sign, rsa_verify
from app.common.utils import hash_password, generate_salt

print("Testing crypto modules...")

# Test DH
p, g = generate_dh_parameters()
print("✓ DH parameters loaded")

# Test AES
import os
key = os.urandom(16)
ct = aes_encrypt("test", key)
pt = aes_decrypt(ct, key)
assert pt.decode() == "test"
print("✓ AES encryption/decryption works")

# Test password hashing
salt = generate_salt()
hash1 = hash_password(salt, "password")
hash2 = hash_password(salt, "password")
assert hash1 == hash2
print("✓ Password hashing consistent")

print("\n✓ All crypto tests passed!")
EOF
```

### Security Tests

#### Test 4: Invalid Certificate Rejection

**Create self-signed certificate:**

```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/fake.key -out /tmp/fake.pem -days 1 -nodes -subj "/CN=Fake"
```

**Replace client certificate temporarily:**

```bash
cp /tmp/fake.pem certs/client_cert.pem
python3 -m app.client
```

**Expected:** Server rejects with `BAD_CERT: Invalid signature`

#### Test 5: Wireshark Packet Capture

**Start Wireshark:**

```bash
sudo wireshark
```

**Capture Setup:**

1. Select **Loopback: lo** interface
2. Apply filter: `tcp.port == 9999`
3. Start capture
4. Run client and server
5. Observe encrypted payloads

**Expected Results:**

- Certificate exchange visible (PEM format)
- DH public values visible
- Message `"ct"` field contains base64 ciphertext
- No plaintext message content visible

#### Test 6: Tampering Detection

**Modify a transcript file:**

```bash
# Backup original
cp transcripts/client_session.txt transcripts/client_session_backup.txt

# Tamper with ciphertext (change one character)
sed -i 's/aGVsbG8=/bGVsbG8=/g' transcripts/client_session.txt

# Attempt verification
python3 scripts/verify_receipt.py \
  receipts/client_receipt.json \
  transcripts/client_session.txt \
  certs/client_cert.pem
```

**Expected:** Verification fails with signature mismatch

#### Test 7: Replay Attack Prevention

**Attempt to replay an old message:**

The system enforces strictly increasing sequence numbers. Any message with `seqno <= last_received_seqno` is rejected with `REPLAY` error.

**Implementation:**

```python
# In server.py
if msg['seqno'] <= client_data['seqno_recv']:
    print(f"[!] REPLAY detected: seqno {msg['seqno']}")
    return None  # Reject message
```

---

## Project Structure

```
securechat-skeleton/
├── app/
│   ├── client.py              # Client implementation
│   ├── server.py              # Server implementation
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── pki.py            # Certificate operations
│   │   ├── dh.py             # Diffie-Hellman key exchange
│   │   ├── aes.py            # AES-128 encryption
│   │   └── sign.py           # RSA digital signatures
│   ├── common/
│   │   ├── __init__.py
│   │   ├── protocol.py       # Message models
│   │   └── utils.py          # Helper functions
│   └── storage/
│       ├── __init__.py
│       ├── db.py             # MySQL operations
│       └── transcript.py     # Transcript management
├── scripts/
│   ├── gen_ca.py             # Generate root CA
│   ├── gen_cert.py           # Generate certificates
│   └── verify_receipt.py     # Offline verification
├── tests/
│   ├── test_tamper.py        # Tampering tests
│   └── test_replay.py        # Replay tests
├── certs/                    # Certificates (gitignored)
│   ├── ca_cert.pem
│   ├── ca_private.key
│   ├── server_cert.pem
│   ├── server_private.key
│   ├── client_cert.pem
│   └── client_private.key
├── transcripts/              # Session logs (gitignored)
├── receipts/                 # SessionReceipts (gitignored)
├── .env                      # Configuration (gitignored)
├── .env.example              # Example configuration
├── .gitignore                # Git ignore rules
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

### Module Descriptions

| Module | Purpose |
|--------|---------|
| `app/crypto/pki.py` | Load/verify X.509 certificates, check expiry |
| `app/crypto/dh.py` | Generate DH parameters, compute shared secret |
| `app/crypto/aes.py` | AES-128 CBC encryption with PKCS#7 padding |
| `app/crypto/sign.py` | RSA-PSS signature generation and verification |
| `app/common/utils.py` | Hashing, encoding, salt generation |
| `app/storage/db.py` | User registration, login verification |
| `app/storage/transcript.py` | Session transcript management |
| `app/client.py` | Client-side protocol implementation |
| `app/server.py` | Server-side protocol implementation |

---

## Security Features

### Cryptographic Primitives

| Primitive | Algorithm | Parameters |
|-----------|-----------|------------|
| Symmetric Encryption | AES-128 | CBC mode, PKCS#7 padding |
| Key Exchange | Diffie-Hellman | 2048-bit safe prime, g=2 |
| Digital Signatures | RSA-2048 | SHA-256 hash, PSS padding |
| Hashing | SHA-256 | 256-bit output |
| PKI | X.509 v3 | Self-signed root CA |

### Security Mechanisms

**Authentication:**
- Mutual certificate verification
- Both client and server validate peer certificates
- Trust established via common CA

**Confidentiality:**
- All credentials encrypted with control plane key
- All messages encrypted with session key
- Keys derived via DH (never transmitted)

**Integrity:**
- SHA-256 digests over message content
- Any tampering breaks signature verification

**Authenticity:**
- RSA signatures prove sender identity
- Only private key holder can generate valid signature

**Replay Protection:**
- Sequence numbers enforced (strictly increasing)
- Duplicate sequence numbers rejected

**Non-Repudiation:**
- Signed transcripts provide cryptographic proof
- SessionReceipts with RSA signatures
- Offline verification possible

### Password Security

```python
# Unique salt per user (16 bytes random)
salt = os.urandom(16)

# Salted SHA-256 hashing
pwd_hash = SHA256(salt || password)

# Stored in database: (email, username, salt, pwd_hash)
```

**Benefits:**
- Rainbow table attacks prevented
- Dictionary attacks require per-user effort
- Database compromise doesn't reveal passwords

---

## Troubleshooting

### Issue 1: Database Connection Failed

**Error:** `MySQL error: Access denied for user 'chatuser'@'localhost'`

**Solution:**

```bash
# Verify user exists
mysql -u root -p -e "SELECT User, Host FROM mysql.user WHERE User='chatuser';"

# Recreate user if needed
mysql -u root -p << 'EOF'
DROP USER IF EXISTS 'chatuser'@'localhost';
CREATE USER 'chatuser'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON securechat.* TO 'chatuser'@'localhost';
FLUSH PRIVILEGES;
EOF

# Update .env with correct password
nano .env
```

### Issue 2: Certificate Verification Failed

**Error:** `BAD_CERT: Invalid signature`

**Solution:**

```bash
# Regenerate all certificates
rm -rf certs/*.pem certs/*.key

python3 scripts/gen_ca.py
python3 scripts/gen_cert.py server
python3 scripts/gen_cert.py client

# Verify chain
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
```

### Issue 3: Import Errors

**Error:** `ModuleNotFoundError: No module named 'app'`

**Solution:**

```bash
# Ensure you're in project root
cd securechat-skeleton

# Activate virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt

# Run with -m flag
python3 -m app.server
```

### Issue 4: Port Already in Use

**Error:** `OSError: [Errno 98] Address already in use`

**Solution:**

```bash
# Find process using port 9999
lsof -i :9999

# Kill the process
kill -9 <PID>

# Or change port in .env
SERVER_PORT=9998
```

### Issue 5: Certificate Expired

**Error:** `BAD_CERT: Certificate expired`

**Solution:**

```bash
# Check certificate validity
openssl x509 -in certs/server_cert.pem -noout -dates

# Regenerate if expired
python3 scripts/gen_cert.py server
python3 scripts/gen_cert.py client
```

---

## Project Status

| Component | Status |
|-----------|--------|
| PKI Setup | ✅ Complete |
| Certificate Generation | ✅ Complete |
| Database Integration | ✅ Complete |
| Crypto Modules | ✅ Complete |
| Control Plane (Auth) | ✅ Complete |
| Data Plane (Chat) | ✅ Complete |
| Non-Repudiation | ✅ Complete |
| Testing & Evidence | ✅ Complete |
| Documentation | ✅ Complete |

**Overall Status:** ✅ **FULLY IMPLEMENTED AND TESTED**

All CIANR (Confidentiality, Integrity, Authenticity, Non-Repudiation) objectives have been achieved and validated through comprehensive testing including:

- Wireshark packet analysis showing encrypted traffic
- Certificate validation and invalid certificate rejection
- Tampering detection through signature verification
- Replay attack prevention through sequence numbers
- Non-repudiation through signed session transcripts and receipts

**Last Updated:** November 17, 2025

---

## Additional Resources

### Documentation

- [Python Cryptography Library](https://cryptography.io/)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/)
- [MySQL Connector/Python](https://dev.mysql.com/doc/connector-python/en/)

### Standards Referenced

- RFC 5280 - X.509 PKI Certificate
- RFC 3526 - Diffie-Hellman Groups
- NIST FIPS 197 - AES Specification
- PKCS #1 v2.2 - RSA Cryptography

### Course Materials

- Assignment Specification: `IS_Assignment_2.pdf`
- SEED Security Labs: PKI Lab

---

## Contributing

This is an academic assignment completed as part of CS-3002 Information Security course requirements.

**Development Workflow:**
1. Feature branches for each phase
2. Meaningful commit messages
3. Progressive development (10+ commits achieved)
4. No secrets in version control

---

## License

This project is for educational purposes as part of CS-3002 Information Security course at FAST-NUCES.

---

## Author

**Hassan Naqvi**  
Roll Number: 22I-0797  
Email: naqvihassan205@gmail.com  
GitHub: [@naqvihassan](https://github.com/naqvihassan)

**Course:** CS-3002 Information Security  
**Semester:** Fall 2025  
**Institution:** FAST National University of Computer and Emerging Sciences (NUCES)

---

## Acknowledgments

- Course Instructor for comprehensive assignment specifications
- SEED Security Labs for PKI concepts and guidance
- Python cryptography community for excellent libraries and documentation

---

**End of README**
