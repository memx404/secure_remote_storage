import time
import threading

class RateLimiter:
    """
    Basic sliding-window rate limiter.
    Key = user_id or client IP.
    Default: 30 requests/minute per key.
    """
    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max = max_requests
        self.window = window_seconds
        self._lock = threading.Lock()
        self._events = {}  # key -> list[timestamps]

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            arr = self._events.get(key, [])
            # keep only within window
            arr = [t for t in arr if now - t <= self.window]
            if len(arr) >= self.max:
                self._events[key] = arr
                return False
            arr.append(now)
            self._events[key] = arr
            return True
