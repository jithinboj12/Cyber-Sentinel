"""
Detection engine:

- Reads packet dictionaries from a queue.
- Extracts features.
- Queries the model for probability of maliciousness.
- Logs alerts to logs/alerts.log when probability exceeds threshold.
- Optionally triggers mitigation (adds to blocklist, returns mitigation command).
"""

import queue
import threading
import time
import os
from .feature_extractor import extract_features
from ..model_integration.load_model import Detector
from .mitigation import add_to_blocklist, apply_block

ALERTS_LOG = os.path.join(os.path.dirname(__file__), "..", "logs", "alerts.log")
os.makedirs(os.path.dirname(ALERTS_LOG), exist_ok=True)


class DetectionEngine:
    def __init__(self, in_q: queue.Queue, threshold: float = 0.7, mitigation_mode: str = "dry-run"):
        self.in_q = in_q
        self.detector = Detector()
        self.threshold = threshold
        self.mitigation_mode = mitigation_mode
        self._stop_event = threading.Event()
        # ensure log file exists
        with open(ALERTS_LOG, "a") as fh:
            fh.write("")

    def _log_alert(self, alert: dict):
        with open(ALERTS_LOG, "a") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {alert}\n")

    def _handle_mitigation(self, features, prob):
        ip = features.get("src_ip") or features.get("dst_ip")
        add_to_blocklist(ip)
        cmd = apply_block(ip, mode=self.mitigation_mode)
        return cmd

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        return t

    def stop(self):
        self._stop_event.set()

    def _run(self):
        while not self._stop_event.is_set():
            try:
                pkt = self.in_q.get(timeout=1.0)
            except queue.Empty:
                continue
            if pkt is None:
                continue
            if isinstance(pkt, dict) and pkt.get("__error__"):
                # Log the error so the operator sees scapy issues
                self._log_alert({"type": "sniffer_error", "msg": pkt.get("__error__")})
                continue

            features = extract_features(pkt)
            prob = self.detector.predict_proba(features)
            if prob >= self.threshold:
                alert = {
                    "src_ip": features.get("src_ip"),
                    "dst_ip": features.get("dst_ip"),
                    "probability": prob,
                    "features": features,
                }
                cmd = self._handle_mitigation(features, prob)
                alert["mitigation_cmd"] = cmd
                self._log_alert(alert)
