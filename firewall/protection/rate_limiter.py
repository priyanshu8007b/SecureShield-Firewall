"""IP-based rate limiter with auto-blocking."""
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Tuple
import threading


class RateLimiter:
    def __init__(self, max_requests: int = 100,
                 window_seconds: int = 60,
                 block_duration_seconds: int = 300):
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self.block_duration = timedelta(seconds=block_duration_seconds)
        self._requests = defaultdict(list)
        self._blocked = {}
        self._lock = threading.Lock()

    def is_allowed(self, ip: str) -> Tuple[bool, str]:
        with self._lock:
            now = datetime.utcnow()

            if ip in self._blocked:
                if now < self._blocked[ip]:
                    remaining = int((self._blocked[ip] - now).total_seconds())
                    return False, f"Blocked ({remaining}s left)"
                del self._blocked[ip]

            self._requests[ip] = [
                t for t in self._requests[ip] if now - t < self.window
            ]

            if len(self._requests[ip]) >= self.max_requests:
                self._blocked[ip] = now + self.block_duration
                return False, "Rate limit exceeded"

            self._requests[ip].append(now)
            return True, "OK"

    def stats(self) -> dict:
        with self._lock:
            return {
                "tracked_ips": len(self._requests),
                "blocked_ips": len(self._blocked),
            }
