"""
remote.py — Mode REMOTE: Brave/Chrome jalan di DEVICE kamu, server cuma nyetir.

Alur:
1. Di device kamu: jalankan browser dengan --remote-debugging-port=9222
   (script: scripts/device_browser.sh, atau manual)
2. Device daftar ke server: POST /api/remote/register {host, port, label}
3. Server connect ke CDP device, inject cookie profil yang dipilih, buka ChatGPT.
   → Jendela browser muncul DI DEVICE KAMU, sudah login.

Server tidak membuka browser apapun. Server hanya:
- nyimpen profil + cookie (di PROFILES_DIR)
- nyambung ke CDP device lewat tailnet
- inject cookie + navigate

Keamanan akses: endpoint /api/remote/* dibatasi token sederhana (REMOTE_TOKEN).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests

# device yang terdaftar (in-memory cukup; bisa dipersist kalau perlu)
DEVICES: dict[str, dict] = {}


def register_device(host: str, port: int = 9222, label: str = "", token: str = "") -> dict:
    """Daftarkan browser device. Return dict dgn status CDP."""
    if not host:
        return {"ok": False, "error": "host kosong"}
    dev_id = (label or host).strip()
    url = f"http://{host}:{int(port)}"
    ok, info = _cdp_probe(url)
    DEVICES[dev_id] = {
        "id": dev_id, "host": host, "port": int(port), "label": label or host,
        "url": url, "online": ok, "version": info.get("Browser") if ok else None,
        "ua": info.get("User-Agent") if ok else None,
        "registered": int(time.time()), "last_seen": int(time.time()),
    }
    return {"ok": ok, "device": DEVICES[dev_id],
            "error": None if ok else f"CDP tidak bisa dihubungi di {url}"}


def list_devices(refresh: bool = True) -> list[dict]:
    for d in DEVICES.values():
        if refresh:
            ok, info = _cdp_probe(d["url"])
            d["online"] = ok
            if ok:
                d["version"] = info.get("Browser")
                d["ua"] = info.get("User-Agent")
            d["last_seen"] = int(time.time())
    return list(DEVICES.values())


def remove_device(dev_id: str) -> dict:
    if dev_id in DEVICES:
        DEVICES.pop(dev_id)
        return {"ok": True, "removed": dev_id}
    return {"ok": False, "error": "device tidak ada"}


def _cdp_probe(url: str, timeout: float = 4.0) -> tuple[bool, dict]:
    try:
        r = requests.get(f"{url}/json/version", timeout=timeout)
        if r.status_code == 200:
            return True, r.json()
    except Exception:
        pass
    return False, {}


def inject_to_device(dev_id: str, cookies: list[dict], url: str = "https://chatgpt.com/",
                     open_new_tab: bool = True, close_others: bool = False) -> dict:
    """
    Connect ke CDP device, inject cookies, buka url di device.
    Jendela browser muncul DI DEVICE.
    """
    d = DEVICES.get(dev_id)
    if not d:
        # coba cocokkan by host
        for k, v in DEVICES.items():
            if k == dev_id or v["host"] == dev_id:
                d = v
                break
    if not d:
        return {"ok": False, "error": f"device '{dev_id}' belum terdaftar. Klik 'Cek device' dulu."}
    ok, info = _cdp_probe(d["url"])
    if not ok:
        return {"ok": False, "error": f"CDP device offline ({d['url']}). "
                                      f"Pastikan browser di device jalan dgn --remote-debugging-port."}
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"ok": False, "error": f"playwright: {e}"}

    pw = _to_pw(cookies)
    try:
        with sync_playwright() as p:
            b = p.chromium.connect_over_cdp(d["url"])
            ctx = b.contexts[0] if b.contexts else b.new_context()
            ctx.add_cookies(pw)
            pages = ctx.pages
            if open_new_tab or not pages:
                pg = ctx.new_page()
            else:
                pg = pages[0]
            if close_others:
                for other in list(ctx.pages):
                    if other is not pg:
                        try:
                            other.close()
                        except Exception:
                            pass
            pg.goto(url, wait_until="domcontentloaded", timeout=45000)
            title = ""
            try:
                title = pg.title()
            except Exception:
                pass
            return {"ok": True, "device": d["id"], "host": d["host"],
                    "injected": len(pw), "pages": len(ctx.pages), "title": title,
                    "url": pg.url, "browser": info.get("Browser")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _to_pw(cookies: list[dict]) -> list[dict]:
    out = []
    for c in cookies:
        pc = {"name": c.get("name"), "value": c.get("value"),
              "domain": c.get("domain") or ".chatgpt.com",
              "path": c.get("path") or "/"}
        if c.get("secure") is not None:
            pc["secure"] = bool(c["secure"])
        if c.get("httpOnly") is not None:
            pc["httpOnly"] = bool(c["httpOnly"])
        exp = c.get("expiry_epoch") or c.get("expires")
        try:
            if exp and int(exp) > time.time():
                pc["expires"] = int(exp)
        except Exception:
            pass
        out.append(pc)
    return out


DEVICE_SH = r"""#!/usr/bin/env bash
# device_browser.sh — jalankan di DEVICE kamu (laptop/HP/Linux/Mac/Windows-WSL)
# Buka Brave/Chrome dgn remote debugging, biar server bisa nyetir.
set -e
PORT="${1:-9222}"
PROFILE_DIR="${2:-$HOME/.cgpt-device-profile}"
mkdir -p "$PROFILE_DIR"

# cari browser
BIN=""
for c in brave-browser brave google-chrome google-chrome-stable chromium chromium-browser \
         "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
         "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
  if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then BIN="$c"; break; fi
done
if [ -z "$BIN" ]; then
  echo "❌ Brave/Chrome tidak ketemu. Install dulu, atau set BIN manual." >&2
  exit 1
fi

echo "🚀 Browser: $BIN"
echo "🔌 Remote debugging port: $PORT"
echo "👤 Profil device: $PROFILE_DIR"
echo ""
echo "   PENTING: buka port $PORT ke tailnet (device ini). Di Linux:"
echo "   Pastikan bind ke 0.0.0.0 (default Chrome bind 127.0.0.1)."
echo "   Kalau server nggak bisa connect, jalankan: ssh -R $PORT:127.0.0.1:$PORT <server>"
echo ""
exec "$BIN" \
  --remote-debugging-port="$PORT" \
  --remote-debugging-address=0.0.0.0 \
  --remote-allow-origins='*' \
  --user-data-dir="$PROFILE_DIR" \
  --no-first-run --no-default-browser-check \
  --disable-blink-features=AutomationControlled \
  about:blank
"""

TUNNEL_SH = r"""#!/usr/bin/env bash
# tunnel_from_device.sh — jalankan di DEVICE kamu.
# Bikin reverse tunnel: port CDP device di-forward ke server lewat tailnet.
# Jadi server bisa connect ke CDP device tanpa masalah firewall.
set -e
SERVER="${1:-nopauwxp@100.95.162.3}"
PORT="${2:-9222}"
echo "🔁 Reverse tunnel: device:$PORT  ->  server (127.0.0.1:$PORT)"
exec ssh -N -o ServerAliveInterval=20 -o ExitOnForwardFailure=yes \
  -R "127.0.0.1:$PORT:127.0.0.1:$PORT" "$SERVER"
"""


def device_script() -> str:
    return DEVICE_SH


def tunnel_script() -> str:
    return TUNNEL_SH


def instructions(server_ip: str = "100.95.162.3", port: int = 9222) -> dict:
    return {
        "server": f"http://{server_ip}:8787",
        "steps": [
            f"1. DI DEVICE KAMU: jalankan scripts/device_browser.sh {port}",
            f"2. (kalau server tak bisa connect) DI DEVICE: scripts/tunnel_from_device.sh nopauwxp@{server_ip} {port}",
            f"3. DI SERVER/UI: buka tab 🧑‍💻 Banyak Akun → bagian 'Device Remote' → isi host/port → klik 'Cek device'",
            "4. Klik '📡 Buka di device ini' pada akun yang kamu mau → jendela browser muncul DI DEVICE, sudah login.",
        ],
        "notes": [
            "Server tidak membuka browser. Browser 100% jalan di device.",
            "Cookie tetap tersimpan di profil server sebagai backup; tiap kali buka, cookie di-inject ke device.",
            "Kalau kamu mau cookie-nya nempel permanen di device, pakai profil device yg sama terus.",
        ],
    }
