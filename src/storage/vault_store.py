import os
import json
import uuid
from typing import Dict, Tuple

class VaultStore:
    """
    FILE VAULT STORAGE
    ------------------
    Stores encrypted bundles on disk so they can be decrypted later.
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
    def save_bundle(base_storage: str, file_id: str, bundle: Dict) -> str:
        """
        Save encrypted bundle as JSON.
        """
        path = VaultStore.bundle_path(base_storage, file_id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f)
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
    def delete_bundle(base_storage: str, file_id: str) -> None:
        """
        Delete encrypted bundle JSON.
        """
        path = VaultStore.bundle_path(base_storage, file_id)
        if os.path.exists(path):
            os.remove(path)
