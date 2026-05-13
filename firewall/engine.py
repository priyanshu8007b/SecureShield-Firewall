"""Main firewall orchestration engine."""
from typing import Tuple
from collections import deque
import threading

from firewall.preprocessing.normalizer import PayloadNormalizer
from firewall.detectors.rule_engine import RuleEngine
from firewall.detectors.ml_engine import MLEngine
from firewall.protection.rate_limiter import RateLimiter
from firewall.utils.logger import FirewallLogger
import config


class FirewallEngine:
    def __init__(self):
        self.normalizer = PayloadNormalizer()
        self.rule_engine = RuleEngine()
        self.ml_engine = MLEngine(
            config.MODEL_PATH,
            config.VECTORIZER_PATH,
            config.ML_THRESHOLD
        )
        self.rate_limiter = RateLimiter(
            config.RATE_LIMIT_MAX_REQUESTS,
            config.RATE_LIMIT_WINDOW_SECONDS,
            config.RATE_LIMIT_BLOCK_DURATION
        )
        self.logger = FirewallLogger(str(config.LOGS_DIR))

        self._lock = threading.Lock()
        self.total = 0
        self.blocked = 0
        self.allowed = 0
        self.recent = deque(maxlen=50)

    def inspect(self, payload: str, ip: str = "0.0.0.0",
                path: str = "/") -> Tuple[bool, str]:
        """Returns (allowed, reason)."""
        with self._lock:
            self.total += 1

        # 1. Rate limit check
        ok, reason = self.rate_limiter.is_allowed(ip)
        if not ok:
            self._record_block(ip, payload, reason, "rate_limit")
            return False, reason

        # 2. Normalize payload
        normalized = self.normalizer.normalize(payload)

        # 3. Rule-based check
        is_bad, reason = self.rule_engine.check(normalized)
        if is_bad:
            self._record_block(ip, payload, reason, "rule")
            return False, reason

        # 4. ML check
        if self.ml_engine.is_ready():
            is_bad, reason = self.ml_engine.check(normalized)
            if is_bad:
                self._record_block(ip, payload, reason, "ml")
                return False, reason

        # Allowed
        self._record_allow(ip, path)
        return True, "OK"

    def _record_block(self, ip, payload, reason, layer):
        with self._lock:
            self.blocked += 1
            self.recent.appendleft({
                "decision": "BLOCK",
                "ip": ip,
                "payload": payload[:100],
                "reason": reason,
                "layer": layer
            })
        self.logger.block(ip, payload, reason, layer)

    def _record_allow(self, ip, path):
        with self._lock:
            self.allowed += 1
            self.recent.appendleft({
                "decision": "ALLOW",
                "ip": ip,
                "payload": path[:100],
                "reason": "OK",
                "layer": "-"
            })
        self.logger.allow(ip, path)

    def stats(self) -> dict:
        with self._lock:
            block_rate = (self.blocked / self.total * 100) if self.total else 0
            return {
                "total": self.total,
                "blocked": self.blocked,
                "allowed": self.allowed,
                "block_rate": round(block_rate, 2),
                "recent": list(self.recent),
                "rate_limiter": self.rate_limiter.stats(),
                "ml_ready": self.ml_engine.is_ready()
            }
