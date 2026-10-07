"""
Lime BLE unlock PoC.

Implements the full BLE unlock protocol reversed from the Lime app
(v3.282.0, com.limebike.rider).

Protocol flow (from BluetoothVehicle.smali):
  1. Connect to scooter GATT server (scan for local_name / manufacturer_data)
  2. Discover service_uuid
  3. Subscribe to characteristic_uuid notifications
  4. App → scooter: ClientHello (protocol version)
  5. App → scooter: AppKeyInfo (master_key_id, key_valid_since, key_expires_at)
  6. Scooter → app: UnlockAuthRequestMessage (nonce bytes)
  7. App → scooter: UnlockAuthResponse = HMAC-SHA256(app_key, nonce + salt)
  8. Scooter → app: UnlockStatusMessage (success/fail)

Requirements:
  pip install bleak

Usage:
  source venv/bin/activate
  pip install bleak
  python ble_unlock.py \\
    --imei <bike_imei> \\
    --local-name <local_name> \\
    --service-uuid <service_uuid> \\
    --char-uuid <characteristic_uuid> \\
    --master-key-id <master_key_id> \\
    --app-key <app_key_base64> \\
    --salt <salt_hex_or_base64> \\
    --key-valid-since <epoch_ms> \\
    --key-expires-at <epoch_ms>

All values come from the API response of:
  GET /api/rider/v1/trips/{trip_id}/bluetooth_key
"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import struct
import sys

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("Install bleak: pip install bleak")
    sys.exit(1)


# ── Message type constants (from BleMessage$MessageType.smali) ───────────────

MSG_CLIENT_HELLO       = 0x01
MSG_APP_KEY_INFO       = 0x02
MSG_UNLOCK_AUTH_REQ    = 0x03  # scooter → app
MSG_UNLOCK_AUTH_RESP   = 0x04  # app → scooter
MSG_UNLOCK_STATUS      = 0x05  # scooter → app
MSG_LOCK_AUTH_REQ      = 0x06
MSG_LOCK_AUTH_RESP     = 0x07
MSG_LOCK_STATUS        = 0x08


def build_client_hello(protocol_version: int = 2) -> bytes:
    """Send app's max supported protocol version."""
    return bytes([MSG_CLIENT_HELLO, protocol_version])


def build_app_key_info(master_key_id: bytes, valid_since_ms: int, expires_at_ms: int) -> bytes:
    """
    AppKeyInfo payload:
      [type=0x02][master_key_id_len][master_key_id...][valid_since_ms 8B BE][expires_at_ms 8B BE]
    """
    payload = bytes([MSG_APP_KEY_INFO])
    payload += bytes([len(master_key_id)]) + master_key_id
    payload += struct.pack(">Q", valid_since_ms)
    payload += struct.pack(">Q", expires_at_ms)
    return payload


def compute_unlock_response(app_key: bytes, nonce: bytes, salt: bytes) -> bytes:
    """
    HMAC-SHA256(app_key, nonce || salt) — from BluetoothVehicle.smali:
      Mac.getInstance("HmacSHA256")
      SecretKeySpec(app_key, "HmacSHA256")
      mac.init(keySpec)
      mac.doFinal(nonce)   ← salt prepended to nonce in the data
    """
    message = nonce + salt
    digest = hmac.new(app_key, message, hashlib.sha256).digest()
    return bytes([MSG_UNLOCK_AUTH_RESP]) + digest


def decode_key(value: str) -> bytes:
    """Accept base64 or hex."""
    try:
        return base64.b64decode(value)
    except Exception:
        return bytes.fromhex(value)


# ── BLE communication ─────────────────────────────────────────────────────────

async def find_device(local_name: str, imei: str, timeout: float = 15.0):
    print(f"[BLE] Scanning for '{local_name}' (IMEI: {imei}) …")
    devices = await BleakScanner.discover(timeout=timeout)
    for d in devices:
        if local_name and d.name == local_name:
            print(f"[BLE] Found by local_name: {d.address}")
            return d.address
        if imei and d.details:
            mfr = d.metadata.get("manufacturer_data", {})
            for data in mfr.values():
                if imei.encode() in data:
                    print(f"[BLE] Found by IMEI in manufacturer data: {d.address}")
                    return d.address
    return None


async def do_unlock(
    address: str,
    service_uuid: str,
    char_uuid: str,
    master_key_id_raw: bytes,
    app_key: bytes,
    salt: bytes,
    valid_since_ms: int,
    expires_at_ms: int,
) -> bool:
    response_event = asyncio.Event()
    unlock_result: dict = {}

    def notification_handler(sender, data: bytearray):
        msg_type = data[0] if data else 0xFF
        payload = bytes(data[1:])
        print(f"[BLE] ← notification type=0x{msg_type:02x} payload={payload.hex()}")

        if msg_type == MSG_UNLOCK_AUTH_REQ:
            unlock_result["nonce"] = payload
            response_event.set()
        elif msg_type == MSG_UNLOCK_STATUS:
            unlock_result["status"] = payload
            response_event.set()

    async with BleakClient(address) as client:
        print(f"[BLE] Connected to {address}")
        await client.start_notify(char_uuid, notification_handler)

        # Step 1: ClientHello
        hello = build_client_hello()
        print(f"[BLE] → ClientHello: {hello.hex()}")
        await client.write_gatt_char(char_uuid, hello, response=True)
        await asyncio.sleep(0.3)

        # Step 2: AppKeyInfo
        key_info = build_app_key_info(master_key_id_raw, valid_since_ms, expires_at_ms)
        print(f"[BLE] → AppKeyInfo: {key_info.hex()}")
        await client.write_gatt_char(char_uuid, key_info, response=True)

        # Step 3: Wait for nonce challenge
        print("[BLE] Waiting for UnlockAuthRequest nonce …")
        try:
            await asyncio.wait_for(response_event.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            print("[BLE] TIMEOUT waiting for nonce")
            return False

        nonce = unlock_result.get("nonce")
        if not nonce:
            print("[BLE] No nonce received")
            return False

        print(f"[BLE] Received nonce: {nonce.hex()}")

        # Step 4: Compute and send auth response
        response_event.clear()
        auth_resp = compute_unlock_response(app_key, nonce, salt)
        print(f"[BLE] → UnlockAuthResponse: {auth_resp.hex()}")
        await client.write_gatt_char(char_uuid, auth_resp, response=True)

        # Step 5: Wait for UnlockStatus
        try:
            await asyncio.wait_for(response_event.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            print("[BLE] TIMEOUT waiting for unlock status")
            return False

        status = unlock_result.get("status", b"")
        success = len(status) > 0 and status[0] == 0x00
        print(f"[BLE] Unlock status: {status.hex()} → {'SUCCESS ✓' if success else 'FAILED ✗'}")
        return success


# ─────────────────────────────────────────────────────────────────────────────

async def main_async(args):
    master_key_id_raw = decode_key(args.master_key_id)
    app_key           = decode_key(args.app_key)
    salt              = decode_key(args.salt)

    address = await find_device(args.local_name, args.imei)
    if not address:
        print("[ERROR] Scooter not found in BLE scan. Make sure you're within ~3m.")
        sys.exit(1)

    success = await do_unlock(
        address       = address,
        service_uuid  = args.service_uuid,
        char_uuid     = args.char_uuid,
        master_key_id_raw = master_key_id_raw,
        app_key       = app_key,
        salt          = salt,
        valid_since_ms = int(args.key_valid_since),
        expires_at_ms  = int(args.key_expires_at),
    )
    sys.exit(0 if success else 1)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--imei",           required=True)
    p.add_argument("--local-name",     required=True)
    p.add_argument("--service-uuid",   required=True)
    p.add_argument("--char-uuid",      required=True)
    p.add_argument("--master-key-id",  required=True, help="base64 or hex")
    p.add_argument("--app-key",        required=True, help="base64 or hex")
    p.add_argument("--salt",           required=True, help="base64 or hex")
    p.add_argument("--key-valid-since",required=True, help="epoch ms")
    p.add_argument("--key-expires-at", required=True, help="epoch ms")
    args = p.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
