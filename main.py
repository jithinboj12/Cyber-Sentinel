"""
Entry point for the CyberSentinel demo.

What it does:
- Starts the packet sniffer in simulate mode (safe default).
- Starts the detection engine with the demo model.
- Starts the Flask dashboard (optional; run in separate terminal if desired).
- Run with python main.py

Notes:
- For live packet capture or PCAP processing, adjust mode and ensure scapy is installed.
- Mitigation defaults to 'dry-run' - it will append to blocklist.txt and return the command that would be run.
"""

import queue
import threading
import time
import argparse
import os

from realtime.packet_sniffer import start_sniff
from realtime.detection_engine import DetectionEngine
from dashboard.app import app as dashboard_app


def run_dashboard_async():
    t = threading.Thread(target=lambda: dashboard_app.run(host="0.0.0.0", port=5000), daemon=True)
    t.start()
    return t


def main():
    parser = argparse.ArgumentParser(description="CyberSentinel demo")
    parser.add_argument("--mode", choices=["simulate", "pcap", "live"], default="simulate", help="sniff mode")
    parser.add_argument("--pcap", help="pcap file path if mode==pcap")
    parser.add_argument("--iface", help="interface if mode==live")
    parser.add_argument("--threshold", type=float, default=0.75, help="detection probability threshold")
    parser.add_argument("--mitigation", choices=["dry-run", "apply"], default="dry-run", help="mitigation mode")
    parser.add_argument("--no-dashboard", action="store_true", help="don't start local dashboard")
    args = parser.parse_args()

    pkt_q = queue.Queue()
    stop_event = threading.Event()

    # Start sniffer
    sniffer_thread = start_sniff(pkt_q, mode=args.mode, iface=args.iface, pcap=args.pcap, stop_event=stop_event)
    print("Sniffer started (mode=%s)" % args.mode)

    # Start detection engine
    engine = DetectionEngine(pkt_q, threshold=args.threshold, mitigation_mode=args.mitigation)
    engine_thread = engine.start()
    print("Detection engine started (threshold=%.2f)" % args.threshold)

    # Optionally start dashboard
    if not args.no_dashboard:
        dash_thread = run_dashboard_async()
        print("Dashboard available at http://127.0.0.1:5000")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")
        stop_event.set()
        engine.stop()
        time.sleep(0.5)


if __name__ == "__main__":
    main()
