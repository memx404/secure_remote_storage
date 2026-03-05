# Secure Remote Storage (PKI + Encrypted Vault) — Dockerized

A secure file storage service that provides **PKI-based authentication**, **encrypted vault storage**, and **integrity verification** using **digital signatures**. The application is delivered as a Docker Compose stack with an Nginx reverse proxy, a Flask/Gunicorn API, and MongoDB for metadata + audit logs.

---

## Key Security Goals

- **Authentication (PKI):** Per-user identity protected in a **PKCS#12 keystore**.
- **Confidentiality:** Files are encrypted before storage (vault never stores plaintext).
- **Integrity + Non-repudiation:** Files are digitally signed; tampering is detected.
- **Operational visibility:** Audit logs and metadata stored in MongoDB (with disk fallback).
- **Automation:** One command to run the full stack (no manual cert steps required if using cert-generator).

---

## Architecture (High-Level)

**Client → Nginx (TLS) → Flask API (Gunicorn) → Vault + MongoDB**

- Nginx terminates HTTPS (port **443**) and forwards traffic to the web API.
- Flask API handles register/login, upload, list, decrypt, delete.
- Vault stores:
  - `<file_id>.json` encrypted bundle
  - `<file_id>.meta.json` metadata (owner, filename, signature, bundle hash, timestamps)
- MongoDB stores metadata + audit logs (optional for CI; disk fallback remains).

---

## Services & Ports

| Service | Purpose | Port |
|--------|---------|------|
| `nginx` | TLS reverse proxy | `https://localhost:443` |
| `web` | Flask API behind Gunicorn | internal `:5000` |
| `mongo` | metadata + audit logs | `localhost:27017` |
| `mongo-express` | DB UI (admin only) | `http://localhost:8081` |
| `cert-generator` | auto-creates dev TLS certs | none |

---

## Quick Start (Automation First)

### Prerequisites
- Docker Desktop (Windows/Mac) or Docker Engine (Linux)
- Docker Compose v2 (bundled with Docker Desktop)

### 1) Run the full stack (single command)
From the project root:

```bash
docker compose up --build

Then open:

Web App (HTTPS): https://localhost/

Mongo Express: http://localhost:8081

Note: Because certificates are self-signed (dev), your browser will show a warning.
Click Advanced → Proceed.

2) Stop the stack
docker compose down
3) Remove all data (clean reset)

This deletes Mongo data + vault data volumes (use carefully):

docker compose down -v
TLS Certificates (Automated)

This project requires TLS certs for Nginx:

nginx/certs/server.crt

nginx/certs/server.key

Recommended: Auto-generate (cert-generator)

If your docker-compose.yml includes the cert-generator service, certificates are created automatically the first time you run:

docker compose up --build
Manual alternative: generate_certs.py

If you prefer manual generation:

python generate_certs.py
docker compose up --build
API Usage (Core Endpoints)

Base path is routed through Nginx over HTTPS. Typical endpoints include:

POST /api/register

POST /api/login

POST /api/upload (multipart form-data: file, password)

POST /api/files

POST /api/decrypt/<file_id>

POST /api/delete/<file_id>

The API uses a Bearer token after login.
Requests must include:

Authorization: Bearer <token>

X-Request-Id: <unique_nonce> (replay protection)

Data Storage Layout

Within the container volume:

secure_storage/
  ├── keystore/        # PKCS#12 user identities
  ├── ca/              # local CA assets
  └── vault/           # encrypted files + metadata
        ├── <id>.json
        └── <id>.meta.json
Persistence behavior

Local runtime: data remains until you run docker compose down -v.

CI tests: use temporary test storage and clean up after finishing.

CI Pipeline (GitHub Actions)

CI performs:

Python dependency install

Pytest test suite

Docker Compose build (validates deployment configuration)

This ensures:

Tests validate crypto, routes, storage, and security behavior.

The deployment stack builds exactly as it runs locally.

Common Troubleshooting
1) “Bad Gateway” in browser

This usually means Nginx cannot reach the web container.

Check:

docker compose ps
docker logs srs_server --tail 80
docker logs srs_proxy --tail 80
2) Browser HTTPS warning

Expected for self-signed dev certs.
Proceed via Advanced in the browser.

3) Mongo not available

The API includes disk fallback for file listing and decrypt metadata.
Mongo is still recommended for audit logs and richer querying.

4) Clean rebuild
docker compose down -v
docker compose up --build

Security Notes (Scope)

Self-signed certificates are for development/testing.

Production should use:

a trusted CA (Let’s Encrypt / enterprise CA),

hardened secrets management,

and external certificate validation (OCSP/CRL) if required.