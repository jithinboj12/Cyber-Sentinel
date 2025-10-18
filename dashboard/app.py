"""
A minimal Flask dashboard that displays recent alerts and the blocklist.
Safe: the dashboard only reads logs and blocklist files; it does not perform control-plane operations.
"""

from flask import Flask, jsonify, render_template_string
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
ALERTS_LOG = os.path.join(BASE_DIR, "logs", "alerts.log")
BLOCKLIST = os.path.join(os.path.dirname(__file__), "blocklist.txt")

app = Flask(__name__)

_SIMPLE_TEMPLATE = """
<!doctype html>
<title>CyberSentinel Dashboard</title>
<h1>CyberSentinel - Recent Alerts</h1>
<p>Threshold-based AI detection. This demo only shows collected alerts and blocklist entries.</p>
<h2>Recent Alerts</h2>
<pre style="background:#111;color:#bada55;padding:8px;max-height:400px;overflow:auto;">
{{alerts}}
</pre>
<h2>Blocklist</h2>
<pre style="background:#111;color:#f1c40f;padding:8px;">
{{blocklist}}
</pre>
"""


def _read_file(path):
    if not os.path.exists(path):
        return ""
    with open(path, "r") as fh:
        return fh.read()


@app.route("/")
def index():
    alerts = _read_file(ALERTS_LOG)
    blocklist = _read_file(BLOCKLIST)
    return render_template_string(_SIMPLE_TEMPLATE, alerts=alerts or "(no alerts yet)", blocklist=blocklist or "(empty)")


@app.route("/api/alerts")
def api_alerts():
    return jsonify({"alerts": _read_file(ALERTS_LOG)})


@app.route("/api/blocklist")
def api_blocklist():
    return jsonify({"blocklist": _read_file(BLOCKLIST)})


if __name__ == "__main__":
    app.run(port=5000, debug=False)
