# Secure Remote Storage (SRS)

A secure, CLI-based file storage system implementing hybrid encryption (AES-256 + RSA-2048) and a secure client-server architecture. Developed for the ST6051CEM Practical Cryptography module.

## 🚀 Features
* **Hybrid Encryption:** AES-256 (CBC) for data confidentiality and RSA-2048 (OAEP) for secure key exchange.
* **Transport Security:** Full HTTPS/TLS encryption using Nginx reverse proxy.
* **Secure Deletion:** Anti-forensic wiping of local files after encryption.
* **Networked Storage:** Flask-based REST API server for remote file management.
* **Containerized:** Full Docker support for production-grade deployment.
* **Input Sanitization:** Protects against directory traversal and malicious filenames.

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.10+
* Docker Desktop (Recommended for HTTPS support)
* OpenSSL (Handled via Python dependencies)

### 🔐 Security Setup (Required)
Before running the application, you must generate the local SSL certificates. This acts as a private "Certificate Authority" for the secure tunnel.

1.  **Install Crypto Utilities:**
    ```bash
    pip install -r requirements.txt
    ```
2.  **Generate Certificates:**
    ```bash
    python generate_certs.py
    ```
    *Output: Creates `nginx/certs/server.key` and `server.crt` with Subject Alternative Name (SAN).*

---

### 🐳 Deployment (Docker)
This is the recommended way to run the system as it includes the Nginx Security Proxy.

1.  **Start Services:**
    ```bash
    docker-compose up --build -d
    ```
2.  **Verify Access:**
    * Open browser to: `https://localhost`
    * **Note:** Accept the "Self-Signed Certificate" warning (Advanced -> Proceed).
    * **Success:** You will see the text: `Secure Storage Server is Online!`
3.  **Stop Services:**
    ```bash
    docker-compose down
    ```

### 🐍 Manual Setup (No Docker)
*Only use this if Docker is unavailable. You must disable HTTPS in `src/settings.py` first.*

1.  **Start Server (Terminal 1):** `python -m server.app`
2.  **Start Client (Terminal 2):** `python main.py`

---

## 💻 Usage Guide

The application runs an interactive shell (`SRS-Shell`).

### Key Commands
| Command | Description |
| :--- | :--- |
| `status` | Checks if the secure server (HTTPS) is online. |
| `generate` | Creates a new RSA Identity (Public/Private keys). |
| `encrypt <file>` | Encrypts a file using Hybrid Encryption. |
| `upload <file>` | Uploads an encrypted file to the secure vault. |
| `download <name>` | Downloads a file from the vault. |
| `decrypt -f <file> -k <key>` | Decrypts a file using your private key. |

### Example Workflow
```text
SRS-Shell> status
[+] Server is ONLINE and Secure (HTTPS).

SRS-Shell> generate
[+] Identity generated successfully.

SRS-Shell> encrypt "confidential_report.pdf"
[+] Success. Encrypted to: C:\...\confidential_report.pdf.enc

SRS-Shell> upload "confidential_report.pdf.enc"
[+] Success! Server stored file as: confidential_report.pdf.enc

## 🔧 Troubleshooting
# 1. Stop containers
docker-compose down

# 2. Rebuild Nginx without cache (Forces new cert copy)
docker-compose build --no-cache nginx

# 3. Start services
docker-compose up -d