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
    *Output: Creates `nginx/certs/server.key` and `server.crt`.*

---

### 🐳 Deployment (Docker)
This is the recommended way to run the system as it includes the Nginx Security Proxy.

1.  **Start Services:**
    ```bash
    docker-compose up --build -d
    ```
2.  **Verify Access:**
    * **API:** `https://localhost` (Note the **HTTPS**)
    * **Note:** Your browser may warn about a "Self-Signed Certificate". This is normal for a local development environment.
3.  **Stop Services:**
    ```bash
    docker-compose down
    ```

### 🐍 Manual Setup (Dev Only)
*Note: The client is configured for HTTPS by default. Running manually requires changing `src/config.py` back to HTTP.*

1.  **Start Server:** `python -m server.app`
2.  **Start Client:** `python main.py`

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
[+] System Online: Secure Connection Established (HTTPS).

SRS-Shell> generate
[+] Identity Established: Keys saved to 'keys'

SRS-Shell> encrypt "confidential_report.pdf"
[+] Encryption Successful: confidential_report.pdf.enc created.

SRS-Shell> upload "confidential_report.pdf.enc"
[+] Upload Completed: Server accepted 'confidential_report.pdf.enc'.
