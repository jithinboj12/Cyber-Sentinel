"""
Packet sniffer abstraction.

Modes:
- simulate: generate synthetic packet dictionaries (safe default, no elevated privileges needed)
- pcap: read packets from a .pcap file (requires scapy)
- live: sniff on an interface in real mode (requires scapy and root)

The sniffer pushes packet dictionaries into a queue.Queue instance for downstream processing.
Packet dict keys:
- src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags, timestamp
"""

import time
import random
import threading
import queue
from typing import Dict, Any, Optional


def _make_synthetic_packet() -> Dict[str, Any]:
    protocols = ["TCP", "UDP", "ICMP", "OTHER"]
    tcp_flags = ["", "S", "A", "F", "P", "R"]
    pkt = {
        "src_ip": f"192.0.2.{random.randint(1, 254)}",
        "dst_ip": f"198.51.100.{random.randint(1, 254)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([22, 80, 443, 8080, random.randint(1024, 65535)]),
        "protocol": random.choice(protocols),
        "length": random.randint(40, 1500),
        "tcp_flags": random.choice(tcp_flags),
        "timestamp": time.time(),
    }
    return pkt


def start_sniff(out_q: queue.Queue, mode: str = "simulate", iface: Optional[str] = None, pcap: Optional[str] = None, stop_event: Optional[threading.Event] = None):
    """
    Start sniffing in a background thread.

    - out_q: queue.Queue to put packet dicts into
    - mode: 'simulate' | 'pcap' | 'live'
    - iface: interface name for live mode
    - pcap: path to pcap file for pcap mode
    - stop_event: threading.Event to signal stop
    """

    stop_event = stop_event or threading.Event()

    def _run():
        if mode == "simulate":
            while not stop_event.is_set():
                pkt = _make_synthetic_packet()
                out_q.put(pkt)
                time.sleep(0.05)  # simulate ~20 packets/sec
            return

        # Try scapy-based pcap/live if mode != simulate
        try:
            from scapy.all import sniff, rdpcap, TCP, UDP, IP, ICMP
        except Exception as e:
            out_q.put({"__error__": f"scapy not available: {e}"})
            return

        def _scapy_to_dict(p):
            try:
                ip = p.getlayer(IP)
                proto = "OTHER"
                src_port = None
                dst_port = None
                tcp_flags = ""
                if p.haslayer(TCP):
                    proto = "TCP"
                    src_port = p[TCP].sport
                    dst_port = p[TCP].dport
                    tcp_flags = p[TCP].flags.__str__() if hasattr(p[TCP], "flags") else ""
                elif p.haslayer(UDP):
                    proto = "UDP"
                    src_port = p[UDP].sport
                    dst_port = p[UDP].dport
                elif p.haslayer(ICMP):
                    proto = "ICMP"
                return {
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "src_port": src_port or 0,
                    "dst_port": dst_port or 0,
                    "protocol": proto,
                    "length": len(p),
                    "tcp_flags": tcp_flags,
                    "timestamp": time.time(),
                }
            except Exception:
                return None

        if mode == "pcap":
            if not pcap:
                out_q.put({"__error__": "pcap mode selected but no pcap path provided"})
                return
            try:
                packets = rdpcap(pcap)
            except Exception as e:
                out_q.put({"__error__": f"failed to read pcap: {e}"})
                return
            for p in packets:
                if stop_event.is_set():
                    break
                d = _scapy_to_dict(p)
                if d:
                    out_q.put(d)
            return

        if mode == "live":
            if not iface:
                out_q.put({"__error__": "live mode requires iface"})
                return

            def _callback(p):
                d = _scapy_to_dict(p)
                if d:
                    out_q.put(d)

            sniff(iface=iface, prn=_callback, stop_filter=lambda x: stop_event.is_set())

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread
