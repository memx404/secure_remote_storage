import os
import io
import re
import uuid
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, send_file
from pymongo import MongoClient, ASCENDING
from src.security.hsm import HSM
from src.security.signer import Signer
from src.security.hybrid import HybridCipher
from src.storage.vault_store import VaultStore
from src.security.auth import generate_token, verify_token
from src.security.replay import ReplayGuard
from src.security.rate_limit import RateLimiter
from src.security.revocation import revoke_cert_serial

secure_bp = Blueprint("secure_bp", __name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SRS_API")

BASE_STORAGE = os.getenv("SRS_STORAGE", "secure_storage")
KEYSTORE_DIR = os.path.join(BASE_STORAGE, "keystore")
CA_DIR = os.path.join(BASE_STORAGE, "ca")
os.makedirs(KEYSTORE_DIR, exist_ok=True)
os.makedirs(CA_DIR, exist_ok=True)

# Replay + Rate Limiting 
replay_guard = ReplayGuard(ttl_seconds=int(os.getenv("SRS_NONCE_TTL", "120")))
rate_limiter = RateLimiter(
    max_requests=int(os.getenv("SRS_RL_MAX", "30")),
    window_seconds=int(os.getenv("SRS_RL_WINDOW", "60")),
)

 
db = None
try:
    mongo_user = os.getenv("MONGO_USER", "admin")
    mongo_pass = os.getenv("MONGO_INITDB_ROOT_PASSWORD", "securepassword123")
    mongo_host = os.getenv("MONGO_HOST", "mongo")
    mongo_port = os.getenv("MONGO_PORT", "27017")
    mongo_dbname = os.getenv("MONGO_DB", "srs_db")

    uri = f"mongodb://{mongo_user}:{mongo_pass}@{mongo_host}:{mongo_port}/?authSource=admin"
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    db = client[mongo_dbname]

    db.files.create_index([("owner", ASCENDING)])
    db.files.create_index([("owner", ASCENDING), ("uploaded_at", ASCENDING)])
    db.files.create_index([("file_id", ASCENDING)], unique=True)
    db.audit_logs.create_index([("user", ASCENDING), ("ts", ASCENDING)])
    logger.info("MongoDB connected (%s:%s).", mongo_host, mongo_port)
except Exception as e:
    logger.warning("Mongo disabled: %s", e)
    db = None


def ok(payload=None, code=200):
    data = {"ok": True}
    if payload:
        data.update(payload)
    return jsonify(data), code


def fail(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def audit(event: str, user: str, extra: dict = None):
    if db is None:
        return
    doc = {"event": event, "user": user, "ts": datetime.now(timezone.utc).isoformat()}
    if extra:
        doc.update(extra)
    db.audit_logs.insert_one(doc)


def _payload():
    return request.get_json(silent=True) or request.form


def _user_id():
    p = _payload()
    return (p.get("user_id") or p.get("email") or p.get("username") or "").strip()


def _password():
    p = _payload()
    return (p.get("password") or p.get("pass") or p.get("pwd") or "")


def _file_obj():
    return request.files.get("file") or request.files.get("upload") or request.files.get("document")


def _strong_password(pw: str) -> bool:
    if not pw or len(pw) < 8:
        return False
    if not re.search(r"[A-Z]", pw):
        return False
    if not re.search(r"[a-z]", pw):
        return False
    if not re.search(r"\d", pw):
        return False
    if not re.search(r"[^A-Za-z0-9]", pw):
        return False
    return True


def _rate_key(user: str) -> str:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    return user or ip


def _require_nonce():
    nonce = request.headers.get("X-Request-Id", "").strip()
    if not nonce:
        return False, "Missing X-Request-Id header"
    if not replay_guard.check_and_store(nonce):
        return False, "Replay detected (nonce reused)"
    return True, nonce


def token_required(fn):
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.split(" ", 1)[1].strip() if auth.startswith("Bearer ") else ""
        payload = verify_token(token) if token else None
        user = (payload.get("sub") if payload else "") or ""

        if not rate_limiter.allow(_rate_key(user)):
            return fail("Rate limit exceeded", 429)

        ok_nonce, msg = _require_nonce()
        if not ok_nonce:
            return fail(msg, 400)

        if not payload:
            return fail("Invalid or expired token", 401)

        request.user_id = payload["sub"]
        return fn(*args, **kwargs)

    wrapper.__name__ = fn.__name__
    return wrapper


@secure_bp.route("/health", methods=["GET"])
def health():
    return ok({"status": "OK"})


@secure_bp.route("/register", methods=["POST"])
def register():
    try:
        user = _user_id()
        pw = _password()
        if not user or not pw:
            return fail("user_id/email and password are required", 400)
        if not _strong_password(pw):
            return fail("Weak password. Use 8+ chars with upper, lower, digit, special.", 400)

        HSM.generate_identity(user, pw, KEYSTORE_DIR, CA_DIR)
        audit("REGISTER", user)
        return ok({"message": "Identity Created", "user_id": user}, 201)
    except Exception as e:
        logger.exception("Register failed")
        return fail(f"register failed: {e}", 500)


@secure_bp.route("/login", methods=["POST"])
def login():
    try:
        user = _user_id()
        pw = _password()
        if not user or not pw:
            return fail("user_id/email and password are required", 400)

        _key, _cert, _cas = HSM.load_identity(user, pw, KEYSTORE_DIR)

        token = generate_token(user)
        audit("LOGIN", user)
        return ok({"message": "LOGIN_OK", "user_id": user, "token": token}, 200)
    except FileNotFoundError:
        return fail("Identity not found. Please register first.", 401)
    except ValueError:
        return fail("Invalid username or password", 401)
    except Exception as e:
        logger.exception("Login failed")
        return fail(f"login failed: {e}", 500)


@secure_bp.route("/files", methods=["POST"])
@token_required
def files():
    try:
        user = getattr(request, "user_id", "")
        if not user:
            return fail("token subject missing", 401)

       
        if db is not None:
            docs = list(
                db.files.find(
                    {"owner": user},
                    {"_id": 0, "filename": 1, "file_id": 1, "uploaded_at": 1, "size_bytes": 1, "mime_type": 1},
                ).sort("uploaded_at", -1)
            )
            return ok({"files": docs})

       
        docs = VaultStore.list_files_for_owner(BASE_STORAGE, user)
        return ok({"files": docs})

    except Exception as e:
        logger.exception("Files failed")
        return fail(f"files failed: {e}", 500)


@secure_bp.route("/upload", methods=["POST"])
@token_required
def upload():
    try:
        f = _file_obj()
        user = getattr(request, "user_id", "")
        pw = _password()
        if not f or not user or not pw:
            return fail("file and password required (token user is used)", 400)

        raw = f.read()
        size_bytes = len(raw)
        mime_type = f.mimetype or "application/octet-stream"
        uploaded_at = datetime.now(timezone.utc).isoformat()

        # validate identity
        _ = HSM.load_identity(user, pw, KEYSTORE_DIR)

        # sign plaintext
        sig = Signer.sign_data(raw, user, pw, KEYSTORE_DIR)

        # encrypt plaintext
        bundle = HybridCipher.encrypt_data(raw, user, pw, KEYSTORE_DIR)

        # store encrypted bundle to disk
        file_id = VaultStore.new_file_id()
        bundle_path = VaultStore.save_bundle(BASE_STORAGE, file_id, bundle)

        # hash the stored encrypted bundle
        bundle_hash = VaultStore.sha256_file(bundle_path)

        # store disk metadata (CI fallback)
        VaultStore.save_metadata(
            BASE_STORAGE,
            file_id,
            {
                "file_id": file_id,
                "filename": f.filename,
                "owner": user,
                "signature": sig.hex(),
                "uploaded_at": uploaded_at,
                "size_bytes": size_bytes,
                "mime_type": mime_type,
                "bundle_hash": bundle_hash,
            },
        )

        # store metadata in mongo (if available)
        if db is not None:
            db.files.insert_one(
                {
                    "file_id": file_id,
                    "filename": f.filename,
                    "owner": user,
                    "signature": sig.hex(),
                    "uploaded_at": uploaded_at,
                    "size_bytes": size_bytes,
                    "mime_type": mime_type,
                    "bundle_hash": bundle_hash,
                }
            )

        audit("UPLOAD", user, {"file_id": file_id, "filename": f.filename, "size_bytes": size_bytes})
        return ok(
            {
                "status": "ENCRYPTED_STORED",
                "file_id": file_id,
                "filename": f.filename,
                "uploaded_at": uploaded_at,
                "size_bytes": size_bytes,
                "mime_type": mime_type,
            },
            201,
        )

    except Exception as e:
        logger.exception("Upload failed")
        return fail(f"upload failed: {e}", 500)


@secure_bp.route("/decrypt/<file_id>", methods=["POST"])
@token_required
def decrypt_download(file_id):
    try:
        user = getattr(request, "user_id", "")
        pw = _password()
        if not user or not pw:
            return fail("password required to decrypt", 400)

        if db is not None:
            meta = db.files.find_one(
                {"file_id": file_id, "owner": user},
                {"_id": 0, "filename": 1, "signature": 1, "owner": 1, "bundle_hash": 1},
            )
        else:
            meta = VaultStore.load_metadata(BASE_STORAGE, file_id)
            if meta.get("owner") != user:
                return fail("file not found for this user", 404)

        if not meta:
            return fail("file not found for this user", 404)

        # bundle hash check before decrypt (storage integrity)
        bundle_path = VaultStore.bundle_path(BASE_STORAGE, file_id)
        expected_hash = (meta.get("bundle_hash") or "").strip()
        if expected_hash:
            actual_hash = VaultStore.sha256_file(bundle_path)
            if actual_hash != expected_hash:
                audit("BUNDLE_TAMPER", user, {"file_id": file_id})
                return fail("Encrypted bundle integrity check failed.", 409)

        bundle = VaultStore.load_bundle(BASE_STORAGE, file_id)
        plaintext = HybridCipher.decrypt_data(bundle, user, pw, KEYSTORE_DIR)

        # signature verify
        sig_hex = (meta.get("signature") or "").strip()
        if not sig_hex:
            return fail("missing signature metadata", 500)

        sig = bytes.fromhex(sig_hex)
        if not Signer.verify_signature(plaintext, sig, user, pw, KEYSTORE_DIR):
            audit("INTEGRITY_FAIL", user, {"file_id": file_id})
            return fail("Integrity check failed (signature mismatch). File may be tampered.", 409)

        audit("DECRYPT", user, {"file_id": file_id})
        filename = meta.get("filename", "decrypted_file")

        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=filename,
            mimetype="application/octet-stream",
        )

    except FileNotFoundError:
        return fail("file not found", 404)
    except Exception as e:
        logger.exception("Decryption failed")
        return fail(f"decryption failed: {e}", 500)


@secure_bp.route("/delete/<file_id>", methods=["POST"])
@token_required
def delete_file(file_id):
    try:
        user = getattr(request, "user_id", "")
        if not user:
            return fail("token subject missing", 401)

        if db is not None:
            meta = db.files.find_one({"file_id": file_id, "owner": user}, {"_id": 0})
            if not meta:
                return fail("file not found for this user", 404)
            db.files.delete_one({"file_id": file_id, "owner": user})
        else:
            meta = VaultStore.load_metadata(BASE_STORAGE, file_id)
            if meta.get("owner") != user:
                return fail("file not found for this user", 404)

        VaultStore.delete_bundle(BASE_STORAGE, file_id)
        audit("DELETE", user, {"file_id": file_id})
        return ok({"status": "DELETED", "file_id": file_id})

    except FileNotFoundError:
        return fail("file not found", 404)
    except Exception as e:
        logger.exception("Delete failed")
        return fail(f"delete failed: {e}", 500)


@secure_bp.route("/sign", methods=["POST"])
@token_required
def sign():
    try:
        f = _file_obj()
        user = getattr(request, "user_id", "")
        pw = _password()
        if not f or not user or not pw:
            return fail("file and password required", 400)

        sig = Signer.sign_data(f.read(), user, pw, KEYSTORE_DIR)
        audit("SIGN", user)
        return ok({"signature_hex": sig.hex()})
    except Exception as e:
        logger.exception("Sign failed")
        return fail(f"sign failed: {e}", 500)


@secure_bp.route("/verify", methods=["POST"])
@token_required
def verify():
    try:
        f = _file_obj()
        user = getattr(request, "user_id", "")
        pw = _password()
        sig_hex = (request.form.get("signature") or request.form.get("signature_hex") or "").strip()
        if not sig_hex:
            data = request.get_json(silent=True) or {}
            sig_hex = (data.get("signature") or data.get("signature_hex") or "").strip()

        if not f or not user or not pw or not sig_hex:
            return fail("file, signature, password required", 400)

        sig = bytes.fromhex(sig_hex)
        valid = Signer.verify_signature(f.read(), sig, user, pw, KEYSTORE_DIR)
        audit("VERIFY", user, {"valid": bool(valid)})
        return ok({"valid": bool(valid)})
    except Exception as e:
        logger.exception("Verify failed")
        return fail(f"verify failed: {e}", 500)


@secure_bp.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    try:
        admin_key = os.getenv("SRS_ADMIN_KEY", "")
        provided = request.headers.get("X-Admin-Key", "")
        if not admin_key or provided != admin_key:
            return fail("admin unauthorized", 403)

        user = _user_id()
        pw = _password()
        if not user or not pw:
            return fail("user_id and password required", 400)

        _k, cert, _cas = HSM.load_identity(user, pw, KEYSTORE_DIR)
        revoke_cert_serial(CA_DIR, cert.serial_number)
        audit("REVOKE", user, {"serial": str(cert.serial_number)})
        return ok({"status": "REVOKED", "user_id": user})
    except Exception as e:
        logger.exception("Revoke failed")
        return fail(f"revoke failed: {e}", 500)
