"""Day 3 lab server: a tiny LOCAL-ONLY web app for practising ports, processes,
logs, curl and HTTP header analysis.

Safety rules baked in:
  * binds to 127.0.0.1 only (hardcoded, not configurable)
  * debug mode is off
  * the login credentials below are fake lab values, never reuse them anywhere

Run:   python lab_server.py            -> http://127.0.0.1:5050
Port:  LAB_PORT=5051 python lab_server.py
Log:   lab.log is written next to this file (one line per request)
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, make_response, redirect, request

HOST = "127.0.0.1"  # deliberately hardcoded: this lab never listens on other interfaces
PORT = int(os.environ.get("LAB_PORT", "5050"))
LOG_FILE = Path(__file__).with_name("lab.log")

app = Flask(__name__)


@app.after_request
def write_access_log(resp):  # type: ignore[no-untyped-def]
    """Append one line per request:
    <UTC time> <client ip> <method> <path> <status> <bytes>B "<user agent>"
    Fields are space separated, so awk's $5 is the status code.
    """
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ua = request.headers.get("User-Agent", "-")
    size = resp.calculate_content_length() or 0
    line = f'{stamp} {request.remote_addr} {request.method} {request.path} {resp.status_code} {size}B "{ua}"\n'
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(line)
    return resp


@app.get("/health")
def health():  # type: ignore[no-untyped-def]
    # Returns the server's own PID so you can match it against ss / lsof / ps output.
    return jsonify(status="ok", pid=os.getpid())


@app.get("/headers")
def show_headers():  # type: ignore[no-untyped-def]
    """Echo back the request headers exactly as the server received them."""
    return jsonify(dict(request.headers))


@app.post("/echo")
def echo():  # type: ignore[no-untyped-def]
    """Echo a JSON object back. Rejects anything else with a 400 (never a 500)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Send a JSON object with Content-Type: application/json"), 400
    return jsonify(you_sent=data, content_type=request.content_type)


@app.post("/login")
def login():  # type: ignore[no-untyped-def]
    """Fake login for practising POST + JSON + status codes. Lab credentials only."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Send a JSON object"), 400
    if data.get("username") == "lab-user" and data.get("password") == "lab-password":
        return jsonify(status="authenticated", token="demo-token-not-a-real-secret")
    return jsonify(error="Invalid username or password."), 401


@app.get("/set-cookie")
def set_cookie():  # type: ignore[no-untyped-def]
    """Sets two cookies on purpose. One is configured well, one is not.
    Mission: read the Set-Cookie headers and say which is which, and why."""
    resp = make_response(jsonify(status="cookies set"))
    resp.set_cookie("session_demo", "abc123", httponly=True, samesite="Lax", max_age=3600)
    resp.set_cookie("tracker", "1")  # no HttpOnly, no SameSite, no Max-Age
    return resp


@app.get("/redirect")
def redirect_demo():  # type: ignore[no-untyped-def]
    return redirect("/health", code=302)


@app.get("/slow")
def slow():  # type: ignore[no-untyped-def]
    """Sleep for ?sec=N (capped at 5) so you can measure timings with curl -w."""
    try:
        sec = min(max(float(request.args.get("sec", "2")), 0.0), 5.0)
    except ValueError:
        return jsonify(error="sec must be a number"), 400
    time.sleep(sec)
    return jsonify(status="done", slept=sec)


@app.get("/hardened")
def hardened():  # type: ignore[no-untyped-def]
    """Same idea as /health but with security headers. Compare the two with curl -i."""
    resp = jsonify(status="ok", note="compare my headers with /health")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


if __name__ == "__main__":
    print(f"Lab server on http://{HOST}:{PORT}  (PID {os.getpid()}, log: {LOG_FILE.name})")
    app.run(host=HOST, port=PORT, debug=False)
