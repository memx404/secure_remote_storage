import os
import json
import uuid
import hashlib
from typing import Dict, List, Optional


class VaultStore:
    """
    FILE VAULT STORAGE
    ------------------
    Stores encrypted bundles AND metadata on disk.

    Files created:
      vault/<file_id>.json       -> encrypted bundle JSON
      vault/<file_id>.meta.json  -> metadata JSON (filename, owner, signature, bundle_hash, etc.)
    """

    @staticmethod
    def vault_dir(base_storage: str) -> str:
        path = os.path.join(base_storage, "vault")
        os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def new_file_id() -> str:
        return uuid.uuid4().hex

    @staticmethod
    def bundle_path(base_storage: str, file_id: str) -> str:
        return os.path.join(VaultStore.vault_dir(base_storage), f"{file_id}.json")

    @staticmethod
    def meta_path(base_storage: str, file_id: str) -> str:
        return os.path.join(VaultStore.vault_dir(base_storage), f"{file_id}.meta.json")

    @staticmethod
    def sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _atomic_write_json(path: str, data: Dict) -> None:
        """
        Atomic write to prevent half-written files:
        """
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)

    @staticmethod
    def save_bundle(base_storage: str, file_id: str, bundle: Dict) -> str:
        """
        Save encrypted bundle JSON.
        Returns the bundle file path.
        """
        path = VaultStore.bundle_path(base_storage, file_id)
        VaultStore._atomic_write_json(path, bundle)
        return path

    @staticmethod
    def load_bundle(base_storage: str, file_id: str) -> Dict:
        """
        Load encrypted bundle JSON.
        """
        path = VaultStore.bundle_path(base_storage, file_id)
        if not os.path.exists(path):
            raise FileNotFoundError("Encrypted bundle not found on server.")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def save_metadata(base_storage: str, file_id: str, metadata: Dict) -> str:
        """
        Save metadata JSON.
        Returns metadata file path.
        """
        path = VaultStore.meta_path(base_storage, file_id)
        VaultStore._atomic_write_json(path, metadata)
        return path

    @staticmethod
    def load_metadata(base_storage: str, file_id: str) -> Dict:
        """
        Load metadata JSON.
        """
        path = VaultStore.meta_path(base_storage, file_id)
        if not os.path.exists(path):
            raise FileNotFoundError("Metadata not found for this file.")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def list_files_for_owner(base_storage: str, owner: str) -> List[Dict]:
        """
        Disk-based listing (CI fallback when MongoDB is not available).
        Returns list of metadata dictionaries.
        """
        vdir = VaultStore.vault_dir(base_storage)
        results: List[Dict] = []

        for name in os.listdir(vdir):
            if not name.endswith(".meta.json"):
                continue
            path = os.path.join(vdir, name)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                if meta.get("owner") == owner:
                    results.append(meta)
            except Exception:
                continue

        results.sort(key=lambda x: x.get("uploaded_at", ""), reverse=True)
        return results

    @staticmethod
    def delete_bundle(base_storage: str, file_id: str) -> None:
        """
        Delete both encrypted bundle and metadata.
        """
        bpath = VaultStore.bundle_path(base_storage, file_id)
        mpath = VaultStore.meta_path(base_storage, file_id)

        if os.path.exists(bpath):
            os.remove(bpath)
        if os.path.exists(mpath):
            os.remove(mpath)
