import time
import threading

class ReplayGuard:
    """
    Simple replay protection using X-Request-Id nonces.
    Stores seen nonces for TTL seconds (in-memory).
    """
    def __init__(self, ttl_seconds: int = 120):
        self.ttl = ttl_seconds
        self._lock = threading.Lock()
        self._seen = {}  # nonce -> expires_at

    def check_and_store(self, nonce: str) -> bool:
        """
        Returns True if nonce is NEW; stores it.
        Returns False if nonce already seen (replay).
        """
        now = time.time()
        with self._lock:
            # prune expired
            expired = [k for k, exp in self._seen.items() if exp <= now]
            for k in expired:
                self._seen.pop(k, None)

            if not nonce or nonce in self._seen:
                return False

            self._seen[nonce] = now + self.ttl
            return True
