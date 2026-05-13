"""Structured firewall event logger."""
import logging
import json
from datetime import datetime
from pathlib import Path


class FirewallLogger:
    def __init__(self, log_dir: str = "logs"):
        Path(log_dir).mkdir(exist_ok=True)

        self.json_log = logging.getLogger("firewall.json")
        self.json_log.setLevel(logging.INFO)
        if not self.json_log.handlers:
            jh = logging.FileHandler(f"{log_dir}/events.jsonl")
            jh.setFormatter(logging.Formatter('%(message)s'))
            self.json_log.addHandler(jh)

        self.text_log = logging.getLogger("firewall.text")
        self.text_log.setLevel(logging.INFO)
        if not self.text_log.handlers:
            th = logging.FileHandler(f"{log_dir}/firewall.log")
            th.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s'
            ))
            self.text_log.addHandler(th)

    def block(self, ip: str, payload: str, reason: str, layer: str):
        event = {
            "ts": datetime.utcnow().isoformat(),
            "event": "BLOCK",
            "ip": ip,
            "layer": layer,
            "reason": reason,
            "payload": payload[:500]
        }
        self.json_log.info(json.dumps(event))
        self.text_log.warning(f"BLOCK ip={ip} layer={layer} reason={reason}")

    def allow(self, ip: str, path: str):
        event = {
            "ts": datetime.utcnow().isoformat(),
            "event": "ALLOW",
            "ip": ip,
            "path": path
        }
        self.json_log.info(json.dumps(event))
