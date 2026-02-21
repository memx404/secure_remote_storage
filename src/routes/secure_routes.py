import os
import logging
import io
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, send_file
from pymongo import MongoClient, ASCENDING
from src.security.hsm import HSM
from src.security.signer import Signer
from src.security.hybrid import HybridCipher
from src.storage.vault_store import VaultStore

secure_bp = Blueprint("secure_bp", __name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SRS_API")

BASE_STORAGE = os.getenv("SRS_STORAGE", "secure_storage")
KEYSTORE_DIR = os.path.join(BASE_STORAGE, "keystore")
os.makedirs(KEYSTORE_DIR, exist_ok=True)

db = None
try:
    mongo_pass = os.getenv("MONGO_INITDB_ROOT_PASSWORD", "securepassword123")
    client = MongoClient(f"mongodb://admin:{mongo_pass}@mongo:27017/")
    db = client["srs_db"]

    # ✅ Indexes for performance + clean data model
    db.files.create_index([("owner", ASCENDING)])
    db.files.create_index([("owner", ASCENDING), ("uploaded_at", ASCENDING)])
    db.files.create_index([("file_id", ASCENDING)], unique=True)

    logger.info("MongoDB connected + indexes ensured.")
except Exception as e:
    logger.warning(f"Mongo warning: {e}")

def ok(payload=None, code=200):
    data = {"ok": True}
    if payload:
        data.update(payload)
    return jsonify(data), code

def fail(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code

def _user_id():
    return (request.form.get("user_id")
            or request.form.get("email")
            or request.form.get("username")
            or (request.get_json(silent=True) or {}).get("user_id")
            or (request.get_json(silent=True) or {}).get("email")
            or (request.get_json(silent=True) or {}).get("username")
            or "").strip()

def _password():
    return (request.form.get("password")
            or request.form.get("pass")
            or request.form.get("pwd")
            or (request.get_json(silent=True) or {}).get("password")
            or (request.get_json(silent=True) or {}).get("pass")
            or (request.get_json(silent=True) or {}).get("pwd")
            or "")

def _file_obj():
    return request.files.get("file") or request.files.get("upload") or request.files.get("document")


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

        HSM.generate_identity(user, pw, KEYSTORE_DIR, BASE_STORAGE)
        return ok({"message": "Identity Created", "user_id": user}, 201)
    except Exception as e:
        logger.exception("Register failed")
        return fail(f"register failed: {e}", 500)


@secure_bp.route("/files", methods=["POST"])
def files():
    
    try:
        user = _user_id()
        if not user:
            return fail("user_id/email required", 400)

        if db is None:
            return ok({"files": []})

        docs = list(db.files.find(
            {"owner": user},
            {"_id": 0, "filename": 1, "file_id": 1, "uploaded_at": 1, "size_bytes": 1, "mime_type": 1}
        ).sort("uploaded_at", -1))

        return ok({"files": docs})
    except Exception as e:
        logger.exception("Files failed")
        return fail(f"files failed: {e}", 500)


@secure_bp.route("/upload", methods=["POST"])
def upload():
    """
    Upload + Encrypt + Store
    Mongo schema now includes:
      - uploaded_at (UTC ISO)
      - size_bytes
      - mime_type
    """
    try:
        f = _file_obj()
        user = _user_id()
        pw = _password()
        if not f or not user or not pw:
            return fail("file, user_id/email, password required", 400)

        raw = f.read()
        size_bytes = len(raw)
        mime_type = f.mimetype or "application/octet-stream"
        uploaded_at = datetime.now(timezone.utc).isoformat()

        # Ensure identity exists
        _ = HSM.load_identity(user, pw, KEYSTORE_DIR)

        # Sign plaintext (integrity)
        sig = Signer.sign_data(raw, user, pw, KEYSTORE_DIR)

        # Encrypt plaintext (confidentiality)
        bundle = HybridCipher.encrypt_data(raw, user, pw, KEYSTORE_DIR)

        # Store encrypted bundle on disk
        file_id = VaultStore.new_file_id()
        VaultStore.save_bundle(BASE_STORAGE, file_id, bundle)

        # Store metadata in Mongo
        if db is not None:
            db.files.insert_one({
                "file_id": file_id,
                "filename": f.filename,
                "owner": user,
                "signature": sig.hex(),
                "uploaded_at": uploaded_at,
                "size_bytes": size_bytes,
                "mime_type": mime_type
            })

        return ok({
            "status": "ENCRYPTED_STORED",
            "file_id": file_id,
            "filename": f.filename,
            "uploaded_at": uploaded_at,
            "size_bytes": size_bytes,
            "mime_type": mime_type
        }, 201)

    except Exception as e:
        logger.exception("Upload failed")
        return fail(f"upload failed: {e}", 500)


@secure_bp.route("/decrypt/<file_id>", methods=["POST"])
def decrypt_download(file_id):
    """
    Decrypt + Download file by file_id.
    """
    try:
        user = _user_id()
        pw = _password()
        if not user or not pw:
            return fail("user_id/email and password required", 400)

        if db is None:
            return fail("database not available", 500)

        meta = db.files.find_one({"file_id": file_id, "owner": user}, {"_id": 0, "filename": 1})
        if not meta:
            return fail("file not found for this user", 404)

        bundle = VaultStore.load_bundle(BASE_STORAGE, file_id)
        plaintext = HybridCipher.decrypt_data(bundle, user, pw, KEYSTORE_DIR)

        filename = meta.get("filename", "decrypted_file")
        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=filename,
            mimetype="application/octet-stream"
        )

    except Exception as e:
        logger.exception("Decryption failed")
        return fail(f"decryption failed: {e}", 500)


@secure_bp.route("/delete/<file_id>", methods=["POST"])
def delete_file(file_id):
    """
    Delete encrypted bundle + metadata.
    """
    try:
        user = _user_id()
        pw = _password()
        if not user or not pw:
            return fail("user_id/email and password required", 400)

        if db is None:
            return fail("database not available", 500)

        meta = db.files.find_one({"file_id": file_id, "owner": user}, {"_id": 0})
        if not meta:
            return fail("file not found for this user", 404)

        db.files.delete_one({"file_id": file_id, "owner": user})
        VaultStore.delete_bundle(BASE_STORAGE, file_id)

        return ok({"status": "DELETED", "file_id": file_id})
    except Exception as e:
        logger.exception("Delete failed")
        return fail(f"delete failed: {e}", 500)


@secure_bp.route("/sign", methods=["POST"])
def sign():
    try:
        f = _file_obj()
        user = _user_id()
        pw = _password()
        if not f or not user or not pw:
            return fail("file, user_id/email, password required", 400)

        sig = Signer.sign_data(f.read(), user, pw, KEYSTORE_DIR)
        return ok({"signature_hex": sig.hex()})
    except Exception as e:
        logger.exception("Sign failed")
        return fail(f"sign failed: {e}", 500)


@secure_bp.route("/verify", methods=["POST"])
def verify():
    try:
        f = _file_obj()
        user = _user_id()
        pw = _password()
        sig_hex = (request.form.get("signature") or request.form.get("signature_hex") or "").strip()

        if not sig_hex:
            data = request.get_json(silent=True) or {}
            sig_hex = (data.get("signature") or data.get("signature_hex") or "").strip()

        if not f or not user or not pw or not sig_hex:
            return fail("file, signature, user_id/email, password required", 400)

        sig = bytes.fromhex(sig_hex)
        valid = Signer.verify_signature(f.read(), sig, user, pw, KEYSTORE_DIR)
        return ok({"valid": bool(valid)})
    except Exception as e:
        logger.exception("Verify failed")
        return fail(f"verify failed: {e}", 500)
    
@secure_bp.route("/login", methods=["POST"])
def login():
    try:
        user = _user_id()
        pw = _password()

        if not user or not pw:
            return fail("user_id/email and password are required", 400)

        _ = HSM.load_identity(user, pw, KEYSTORE_DIR)

        return ok({"message": "LOGIN_OK", "user_id": user}, 200)

    except FileNotFoundError:
        return fail("Identity not found. Please register first.", 404)

    except ValueError as e:
        return fail(str(e), 401)

    except Exception as e:
        logger.exception("Login failed")
        return fail(f"login failed: {e}", 500)
