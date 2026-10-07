/**
 * Lime BLE key interceptor — Frida hook
 *
 * Usage:
 *   frida -U -f com.limebike.ridegreen -l frida_hook.js --no-pause
 *   # or on running process:
 *   frida -U com.limebike.ridegreen -l frida_hook.js
 *
 * Hooks:
 *   1. OkHttp3 – logs all HTTP requests + responses (token, body)
 *   2. BluetoothVehicle HMAC – dumps app_key, nonce, salt, computed MAC
 *   3. Trip.BleAuthInfo constructor – dumps raw bluetooth_key API response
 */

"use strict";

// ── 1. OkHttp3 request/response logger ───────────────────────────────────────

Java.perform(() => {

  try {
    const OkHttpClient = Java.use("okhttp3.OkHttpClient");
    const Request = Java.use("okhttp3.Request");
    const Response = Java.use("okhttp3.Response");
    const Buffer = Java.use("okio.Buffer");

    // Hook RealCall.execute so we catch every call
    const RealCall = Java.use("okhttp3.internal.connection.RealCall");
    RealCall.execute.implementation = function () {
      const req = this.request();
      const url = req.url().toString();
      const method = req.method();
      const auth = req.header("Authorization") || "";

      console.log(`\n[HTTP →] ${method} ${url}`);
      if (auth) console.log(`[HTTP ↑] Authorization: ${auth}`);

      const body = req.body();
      if (body) {
        try {
          const buf = Buffer.$new();
          body.writeTo(buf);
          console.log(`[HTTP ↑] Body: ${buf.readUtf8()}`);
        } catch (_) {}
      }

      const resp = this.execute();
      const code = resp.code();
      console.log(`[HTTP ←] ${code} ${url}`);

      // Log response body for key endpoints
      if (url.includes("bluetooth_key") || url.includes("/trips") || url.includes("auth") || url.includes("bootstrap")) {
        try {
          const rb = resp.peekBody(65536);
          if (rb) console.log(`[HTTP ↓] Body: ${rb.string()}`);
        } catch (_) {}
      }

      return resp;
    };
    console.log("[HOOK] OkHttp3 RealCall.execute — OK");
  } catch (e) {
    console.log("[HOOK] OkHttp3 hook failed: " + e);
  }

  // ── 2. HMAC operation dump ─────────────────────────────────────────────────

  try {
    const Mac = Java.use("javax.crypto.Mac");

    Mac.init.overload("java.security.Key").implementation = function (key) {
      this.init(key);
      try {
        const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        if (Java.cast(key, SecretKeySpec)) {
          const encoded = key.getEncoded();
          console.log(`\n[HMAC] Key: ${byteArrayToHex(encoded)}`);
        }
      } catch (_) {}
    };

    Mac.doFinal.overload("[B").implementation = function (data) {
      const result = this.doFinal(data);
      console.log(`[HMAC] Input data (nonce+salt): ${byteArrayToHex(data)}`);
      console.log(`[HMAC] HMAC-SHA256 result:      ${byteArrayToHex(result)}`);
      return result;
    };
    console.log("[HOOK] javax.crypto.Mac — OK");
  } catch (e) {
    console.log("[HOOK] Mac hook failed: " + e);
  }

  // ── 3. BleAuthInfo constructor — raw key material from API ────────────────

  try {
    const BleAuthInfo = Java.use("com.limebike.network.model.response.inner.Trip$BleAuthInfo");
    BleAuthInfo.$init.implementation = function (masterKeyId, appKey, keyValidSince, keyExpiresAt, salt) {
      this.$init(masterKeyId, appKey, keyValidSince, keyExpiresAt, salt);
      console.log("\n[KEY] BleAuthInfo from API:");
      console.log(`  master_key_id:   ${masterKeyId}`);
      console.log(`  app_key:         ${appKey}`);
      console.log(`  key_valid_since: ${keyValidSince}`);
      console.log(`  key_expires_at:  ${keyExpiresAt}`);
      console.log(`  salt:            ${salt}`);
    };
    console.log("[HOOK] Trip$BleAuthInfo constructor — OK");
  } catch (e) {
    console.log("[HOOK] BleAuthInfo hook failed: " + e);
  }

  // ── 4. BluetoothInfo constructor — service/char UUIDs ─────────────────────

  try {
    const BluetoothInfo = Java.use("com.limebike.network.model.response.inner.Trip$BluetoothInfo");
    BluetoothInfo.$init.implementation = function (serviceUuid, charUuid, mfrDataKey, bikeImei, localName, bleAuthInfo, config) {
      this.$init(serviceUuid, charUuid, mfrDataKey, bikeImei, localName, bleAuthInfo, config);
      console.log("\n[KEY] BluetoothInfo:");
      console.log(`  service_uuid:   ${serviceUuid}`);
      console.log(`  char_uuid:      ${charUuid}`);
      console.log(`  bike_imei:      ${bikeImei}`);
      console.log(`  local_name:     ${localName}`);
    };
    console.log("[HOOK] Trip$BluetoothInfo constructor — OK");
  } catch (e) {
    console.log("[HOOK] BluetoothInfo hook failed: " + e);
  }

});

function byteArrayToHex(arr) {
  return Array.from(arr).map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}
