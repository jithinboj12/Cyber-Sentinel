"""
Feature extractor: converts incoming packet dicts into model-ready numeric features.

This file contains functions that:
- normalize ports, lengths and time
- map protocol to standardized strings
- return a flat dict matching feature_mapping.json keys
"""

import datetime
import ipaddress


def normalize_time_of_day(ts: float) -> float:
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1e6


def _normalize_protocol(proto_raw):
    if not proto_raw:
        return "OTHER"
    p = str(proto_raw).upper()
    if "TCP" in p:
        return "TCP"
    if "UDP" in p:
        return "UDP"
    if "ICMP" in p:
        return "ICMP"
    return "OTHER"


def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default


def extract_features(packet: dict) -> dict:
    """
    Accepts a packet dict (as produced by packet_sniffer), returns a feature dict.
    """
    pkt = packet
    features = {}
    features["src_ip"] = pkt.get("src_ip", "0.0.0.0")
    features["dst_ip"] = pkt.get("dst_ip", "0.0.0.0")
    features["src_port"] = safe_int(pkt.get("src_port", 0))
    features["dst_port"] = safe_int(pkt.get("dst_port", 0))
    features["protocol"] = _normalize_protocol(pkt.get("protocol"))
    features["length"] = safe_int(pkt.get("length", 0))
    features["tcp_flags"] = str(pkt.get("tcp_flags", "")) if pkt.get("tcp_flags") else ""
    features["time_of_day"] = normalize_time_of_day(pkt.get("timestamp", __import__("time").time()))
    return features
