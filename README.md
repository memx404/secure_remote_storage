# Secure Remote Storage (SRS)

A secure, CLI-based file storage system implementing hybrid encryption (AES-256 + RSA-2048) and a client-server architecture. Developed for the ST6051CEM Practical Cryptography module.

## 🚀 Features
* **Hybrid Encryption:** AES-256 (CBC) for data confidentiality and RSA-2048 (OAEP) for secure key exchange.
* **Secure Deletion:** Anti-forensic wiping of local files after encryption.
* **Networked Storage:** Flask-based REST API server for remote file management.
* **Containerized:** Full Docker support for portable deployment.
* **Input Sanitization:** Protects against directory traversal and malicious filenames.

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.10+
* Docker Desktop (Optional, for containerized run)

### Option 1: Manual Setup (Local Python)
Use this for development and debugging.

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
2.  **Start the Server:**
    Open a terminal and run:
    ```bash
    python -m server.app
    ```
3.  **Run the Client:**
    Open a second terminal and run:
    ```bash
    python main.py
    ```

### Option 2: Docker Deployment (Recommended)
Use this to simulate a production environment.

1.  **Start Services:**
    ```bash
    docker-compose up --build -d
    ```
2.  **Verify Access:**
    The API will be available at: `http://localhost:5000`
    *Note: Uploaded files are persisted in `server/storage/`.*
3.  **Stop Services:**
    ```bash
    docker-compose down
    ```

## 💻 Usage Guide

The application runs an interactive shell (`SRS-Shell`).

### key Commands
| Command | Description |
| :--- | :--- |
| `status` | Checks if the remote server is online. |
| `generate` | Creates a new RSA Identity (Public/Private keys). |
| `encrypt <file>` | Encrypts a file using Hybrid Encryption. |
| `upload <file>` | Uploads an encrypted file to the server. |
| `download <name>` | Downloads a file from the server. |
| `decrypt -f <file> -k <key>` | Decrypts a file using your private key. |

### Example Workflow
```text
SRS-Shell> generate
SRS-Shell> encrypt "my_secret.pdf"
SRS-Shell> upload "my_secret.pdf.enc"
SRS-Shell> download "my_secret.pdf.enc"
