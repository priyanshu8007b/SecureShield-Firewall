"""Flask dashboard for SecureShield."""
from flask import Flask, render_template, request, jsonify

from firewall.engine import FirewallEngine

app = Flask(__name__)
engine = FirewallEngine()


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(engine.stats())


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json() or {}
    payload = data.get("payload", "")
    ip = request.remote_addr or "0.0.0.0"
    allowed, reason = engine.inspect(payload, ip=ip, path="/api/check")
    return jsonify({
        "allowed": allowed,
        "reason": reason,
        "payload": payload
    })


def run(host="0.0.0.0", port=5000):
    app.run(host=host, port=port, debug=False)
