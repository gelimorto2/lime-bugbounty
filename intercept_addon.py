"""
Lime API mitmproxy addon.

Usage:
  source venv/bin/activate
  mitmproxy -s intercept_addon.py --listen-port 8080

On the Android device/emulator:
  - Set HTTP proxy to <host-ip>:8080
  - Install ~/.mitmproxy/mitmproxy-ca-cert.pem to device user store
    (not needed for Lime — network_security_config.xml already trusts user certs)

Captured tokens and API calls are written to lime_traffic.log
"""

import json
import logging
import re
from mitmproxy import http

TARGET_HOST = "web-production.lime.bike"
LOG_FILE = "lime_traffic.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)


def _is_lime(flow: http.HTTPFlow) -> bool:
    host = flow.request.pretty_host
    return "lime.bike" in host or "limecloudflare.com" in host


def request(flow: http.HTTPFlow) -> None:
    if not _is_lime(flow):
        return

    auth = flow.request.headers.get("Authorization", "")
    token = re.sub(r"^Bearer\s+", "", auth).strip()

    entry = {
        "direction": "REQUEST",
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "token": token or None,
        "body": _safe_body(flow.request),
    }
    logging.info(json.dumps(entry))
    print(f"[LIME] {flow.request.method} {flow.request.path}")


def response(flow: http.HTTPFlow) -> None:
    if not _is_lime(flow):
        return

    entry = {
        "direction": "RESPONSE",
        "status": flow.response.status_code,
        "url": flow.request.pretty_url,
        "body": _safe_body(flow.response),
    }
    logging.info(json.dumps(entry))

    # Print high-value responses immediately
    path = flow.request.path
    if any(kw in path for kw in ["bluetooth_key", "/trips", "auth", "token", "bootstrap"]):
        print(f"[LIME ★] {flow.response.status_code} {path}")
        body = _safe_body(flow.response)
        if body:
            print(json.dumps(body, indent=2)[:800])


def _safe_body(msg) -> dict | str | None:
    try:
        return json.loads(msg.content)
    except Exception:
        text = msg.content.decode("utf-8", errors="replace")
        return text[:500] if text else None
