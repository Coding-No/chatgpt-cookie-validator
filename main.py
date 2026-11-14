"""
ChatGPT Cookie Validator + Session Login URL Generator  (v2.0)
Backend: FastAPI

Fitur v2:
- /                    UI web (paste cookie -> cek -> verdict -> URL login)
- POST /api/check      validasi + verdict + URL
- POST /api/export/bundle   download HTML login bundle
- POST /api/batch      batch: banyak cookie sekaligus -> hasil semua -> export CSV/JSON
- POST /api/brave/inject    auto-login: inject cookie ke Brave (CDP/Playwright) + buka ChatGPT
- GET  /api/brave/status    status Brave CDP
- GET  /api/batch/export    unduh hasil batch terakhir (csv)
- Endpoint publik: jalankan uvicorn --host 0.0.0.0 (lihat run.sh)
"""
from __future__ import annotations
import base64, json, time, uuid, hashlib, os, csv, io, threading, subprocess, shutil, re
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from auto_parse import auto_parse, sniff_format
from pydantic import BaseModel
import requests

app = FastAPI(title="ChatGPT Cookie Validator", version="2.0.0")

BASE = "https://chatgpt.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TIMEOUT = 25
WORKDIR = Path(__file__).resolve().parent
BATCH_STORE = WORKDIR / "batch_last.json"      # hasil batch terakhir
BRAVE_PROFILE = Path("/tmp/brave-rt-profile")   # profil ISOLASI (tidak sentuh profil user)
CDP_PORT = int(os.environ.get("BRAVE_CDP_PORT", "9333"))


# =============================== models ===============================
class CookieIn(BaseModel):
    raw: str = ""
    json_dump: dict[str, Any] | None = None


class BatchIn(BaseModel):
    raw: str = ""            # banyak blok cookie dipisah baris "=== <label> ===" atau newline ganda
    items: list[dict] | None = None   # [{label, raw}]
    concurrency: int = 4


class BraveInjectIn(BaseModel):
    raw: str = ""
    json_dump: dict[str, Any] | None = None
    open_url: str = f"{BASE}/"
    portable: bool = True


# ============================== parsing ===============================
def parse_netscape(raw: str) -> list[dict]:
    out: list[dict] = []
    for line in (raw or "").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        p = line.rstrip("\n").split("\t")
        if len(p) != 7:
            continue
        dom, sub, path, sec, exp, name, val = p
        c = {"name": name, "value": val, "domain": dom, "path": path or "/",
             "secure": sec.upper() == "TRUE", "httpOnly": False, "sameSite": "Lax"}
        if exp.isdigit() and int(exp) > 0:
            c["expires"] = int(exp)
        out.append(c)
    return out


def parse_json_dump(d: dict | None) -> list[dict]:
    if not d:
        return []
    if isinstance(d, dict) and isinstance(d.get("cookies"), list):
        return [c for c in d["cookies"] if "name" in c and "value" in c]
    if isinstance(d, list):
        return [c for c in d if isinstance(c, dict) and "name" in c and "value" in c]
    return []


def parse_any(raw: str = "", json_dump: dict | None = None) -> list[dict]:
    """Wrapper lama — tetap ada untuk kompatibilitas. Pakai auto-detect di bawah."""
    if (raw or "").strip():
        batches = auto_parse(raw)
        return [c for b in batches for c in b["cookies"]]
    return parse_json_dump(json_dump)


def auto_batches(raw: str = "", json_dump: dict | None = None) -> list[dict]:
    """Auto-detect multi-format -> list batch [{label,format,cookies}]."""
    if (raw or "").strip():
        return auto_parse(raw)
    if json_dump:
        cks = parse_json_dump(json_dump) or auto_parse(json.dumps(json_dump))[0]["cookies"] \
            if isinstance(json_dump, dict) else parse_json_dump(json_dump)
        if not cks:
            bl = auto_parse(json.dumps(json_dump))
            cks = [c for b in bl for c in b["cookies"]]
        if cks:
            return [{"label": "json-input", "format": "json", "cookies": cks}]
    return []


def cookie_dict(cookies: list[dict]) -> dict[str, str]:
    return {c["name"]: c["value"] for c in cookies}


def to_playwright(cookies: list[dict]) -> list[dict]:
    pw = []
    for c in cookies:
        item = {"name": c["name"], "value": c["value"], "domain": c["domain"],
                "path": c.get("path", "/"), "secure": c.get("secure", False),
                "httpOnly": c.get("httpOnly", False),
                "sameSite": c.get("sameSite", "Lax")}
        if c.get("expires"):
            item["expires"] = int(c["expires"])
        pw.append(item)
    return pw


# =========================== offline check ============================
def offline_check(cookies: list[dict]) -> dict:
    now = int(time.time())
    rows, alive, expired = [], 0, 0
    for c in cookies:
        exp = c.get("expires", 0)
        if exp and int(exp) > 0:
            status = "ALIVE" if int(exp) > now else "EXPIRED"
            alive += status == "ALIVE"
            expired += status == "EXPIRED"
        else:
            status = "SESSION"
        rows.append({"name": c["name"], "domain": c["domain"],
                     "secure": c.get("secure", False), "httpOnly": c.get("httpOnly", False),
                     "expiry_epoch": exp, "status": status})
    return {"total": len(cookies), "alive": alive, "expired": expired, "rows": rows}


# ============================ live verify =============================
def _session(cookies: list[dict], did: str):
    s = requests.Session()
    s.cookies.update(cookie_dict(cookies))
    s.headers.update({"user-agent": UA, "origin": BASE, "referer": BASE + "/",
                      "oai-device-id": did, "oai-language": "en-US", "accept": "*/*"})
    return s, s.get(f"{BASE}/api/auth/session", timeout=TIMEOUT)


def live_verify(cookies: list[dict]) -> dict:
    ck = cookie_dict(cookies)
    did = ck.get("oai-did") or str(uuid.uuid4())
    result: dict[str, Any] = {"device_id": did, "session": None, "user": None,
                              "access_token_len": 0, "backend": [], "verdict": "UNKNOWN",
                              "verdict_reason": "", "error": None}
    try:
        s, r = _session(cookies, did)
        result["session_status"] = r.status_code
        if r.status_code == 200:
            j = r.json()
            result["user"] = j.get("user")
            result["expires"] = j.get("expires")
            tok = j.get("accessToken") or ""
            result["access_token_len"] = len(tok)
        else:
            result["error"] = f"session endpoint {r.status_code}"
            result["verdict"] = "INVALID"
            result["verdict_reason"] = f"/api/auth/session -> {r.status_code}"
            return result
    except Exception as e:
        result["error"] = str(e)
        result["verdict"] = "ERROR"
        result["verdict_reason"] = f"koneksi gagal: {e}"
        return result

    if not result.get("access_token_len"):
        result["verdict"] = "PARTIAL"
        result["verdict_reason"] = "session ada tapi tanpa accessToken"
        return result

    H = {"Authorization": f"Bearer {tok}", "oai-device-id": did, "accept": "*/*"}
    endpoints = {
        "me": f"{BASE}/backend-api/me",
        "models": f"{BASE}/backend-api/models",
        "accounts_check": f"{BASE}/backend-api/accounts/check/v4-2023-04-27",
        "conversations": f"{BASE}/backend-api/conversations?offset=0&limit=5",
    }
    any_ok, all_deny, err_code = False, True, None
    for tag, url in endpoints.items():
        try:
            r = s.get(url, headers=H, timeout=TIMEOUT)
        except Exception as e:
            result["backend"].append({"endpoint": tag, "status": 0, "error": str(e)})
            continue
        entry = {"endpoint": tag, "status": r.status_code}
        if r.status_code == 200:
            any_ok = True
            all_deny = False
            try:
                d = r.json()
                if tag == "models":
                    entry["models"] = [m.get("slug") for m in d.get("models", [])][:12]
                elif tag == "conversations":
                    entry["total"] = d.get("total")
                elif tag == "accounts_check":
                    acc = d.get("accounts", {})
                    entry["plan"] = [i.get("account", {}).get("plan_type")
                                     for i in list(acc.values())[:2]]
            except Exception:
                pass
        else:
            try:
                e = r.json().get("error", {})
                entry["code"] = e.get("code")
                err_code = err_code or e.get("code")
            except Exception:
                entry["body"] = r.text[:120]
        result["backend"].append(entry)

    if any_ok:
        result["verdict"] = "VALID"
        result["verdict_reason"] = "access token hidup, backend dapat diakses"
    elif all_deny and err_code == "token_revoked":
        result["verdict"] = "REVOKED"
        result["verdict_reason"] = ("session cookie masih ada (profil stale terembalikan) "
                                    "TAPI access token sudah di-revoke server-side")
    elif all_deny:
        result["verdict"] = "DENIED"
        result["verdict_reason"] = f"backend menolak (code={err_code or 'n/a'})"
    return result


# =========================== URL builder ==============================
def build_login_urls(cookies: list[dict]) -> dict:
    ck = cookie_dict(cookies)
    pw = to_playwright(cookies)
    bundle = {"url": f"{BASE}/", "url_api_session": f"{BASE}/api/auth/session",
              "cookie_json_playwright": pw,
              "cookie_header": "; ".join(f"{k}={v}" for k, v in ck.items())}
    js = ("// Paste di Console browser yang SUDAH di origin https://chatgpt.com\n"
          "(async () => {\n"
          f"  const cookies = {json.dumps(pw)};\n"
          "  const set = c => {\n"
          "    const exp = c.expires ? '; expires='+new Date(c.expires*1000).toUTCString() : '';\n"
          "    document.cookie = `${c.name}=${c.value}; path=${c.path||'/'}${exp}`\n"
          "      + (c.domain.startsWith('.') ? `; domain=${c.domain}` : '')\n"
          "      + (c.secure ? '; Secure' : '') + '; SameSite=Lax';\n"
          "  };\n"
          "  cookies.filter(c=>!c.httpOnly).forEach(set);\n"
          "  location.href='https://chatgpt.com/';\n"
          ")();\n")
    return {**bundle, "bookmarklet_console_js": js,
            "curl_session": (f"curl -s '{BASE}/api/auth/session' "
                             f"-b '{bundle['cookie_header']}' -H 'user-agent: {UA}' | jq ."),
            "playwright_snippet": ("ctx.add_cookies(COOKIE_JSON_PLAYWRIGHT)\n"
                                   "pg = ctx.new_page(); pg.goto('https://chatgpt.com/')\n")}


# =========================== batch helpers ============================
def split_batch(raw: str) -> list[dict]:
    """Pisah input batch — AUTO-DETECT (Netscape multi-blok, JSON, header-string, campur)."""
    batches = auto_parse(raw)
    if len(batches) > 1:
        return [{"label": b["label"], "raw": None, "cookies": b["cookies"],
                 "format": b["format"]} for b in batches]
    # single batch: tetap pakai splitter delimiter lama kalau ada banyak blok
    items: list[dict] = []
    if re.search(r'^\s*===\s*.+?\s*===\s*$', raw, re.M):
        parts = re.split(r'^\s*===\s*(.+?)\s*===\s*$', raw, flags=re.M)
        for i in range(1, len(parts) - 1, 2):
            label, body = parts[i].strip(), parts[i + 1].strip()
            if body:
                items.append({"label": label, "raw": body, "cookies": None, "format": None})
    return items


def verify_one(label: str, raw: str, cookies: list[dict] | None = None,
               fmt: str | None = None) -> dict:
    cookies = cookies if cookies else parse_any(raw=raw)
    if not cookies:
        return {"label": label, "ok": False, "verdict": "PARSE_ERROR", "format": fmt or "unknown",
                "verdict_reason": "tidak ada cookie ter-parse", "user_email": None,
                "token_len": 0, "backend_codes": "", "cookie_count": 0}
    off = offline_check(cookies)
    live = live_verify(cookies)
    u = live.get("user") or {}
    codes = ";".join(f"{b['endpoint']}={b.get('status')}:{b.get('code','')}"
                     for b in live.get("backend", []))
    return {"label": label, "ok": True, "verdict": live["verdict"], "format": fmt or "auto",
            "verdict_reason": live["verdict_reason"], "user_email": u.get("email"),
            "user_name": u.get("name"), "user_id": u.get("id"),
            "expires": live.get("expires"), "token_len": live.get("access_token_len", 0),
            "cookie_alive": off["alive"], "cookie_expired": off["expired"],
            "cookie_count": off["total"], "backend_codes": codes,
            "device_id": live.get("device_id")}


# ============================ Brave inject ============================
BRAVE_CANDIDATES = [
    os.environ.get("BRAVE_BIN", ""),
    "/usr/bin/brave-browser", "/usr/bin/brave",
    "/opt/brave.com/brave/brave",
    "/var/lib/flatpak/app/com.brave.Browser/current/active/files/extra/brave",
    str(Path.home() / ".local/share/flatpak/app/com.brave.Browser/current/active/files/extra/brave"),
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
]


def find_brave() -> str | None:
    for p in BRAVE_CANDIDATES:
        if p and os.path.exists(p) and os.access(p, os.X_OK):
            return p
    for name in ("brave-browser", "brave"):
        w = shutil.which(name)
        if w:
            return w
    # flatpak?
    try:
        r = subprocess.run(["flatpak", "info", "com.brave.Browser"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return "flatpak:com.brave.Browser"
    except Exception:
        pass
    return None


def cdp_alive() -> dict:
    try:
        r = requests.get(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=4)
        if r.status_code == 200:
            return {"alive": True, "info": r.json()}
    except Exception as e:
        return {"alive": False, "error": str(e)}
    return {"alive": False}


def launch_brave_cdp(port: int = CDP_PORT) -> dict:
    """Launch Brave dengan CDP + profil isolasi. Return status."""
    st = cdp_alive()
    if st.get("alive"):
        return {"launched": False, "already": True, **st}
    brave = find_brave()
    if not brave:
        return {"launched": False, "error": "Brave binary tidak ditemukan"}
    BRAVE_PROFILE.mkdir(parents=True, exist_ok=True)
    common = [f"--user-data-dir={BRAVE_PROFILE}", f"--remote-debugging-port={port}",
              "--remote-allow-origins=*", "--headless=new", "--no-sandbox",
              "--disable-gpu", "--no-first-run", "--no-default-browser-check",
              "--disable-blink-features=AutomationControlled", "about:blank"]
    if brave.startswith("flatpak:"):
        app = brave.split(":", 1)[1]
        cmd = ["flatpak", "run", app] + common
    else:
        cmd = [brave] + common
    log = open(WORKDIR / "brave_cdp.log", "ab")
    subprocess.Popen(cmd, stdout=log, stderr=log, start_new_session=True)
    # tunggu CDP up
    for _ in range(20):
        time.sleep(1.5)
        if cdp_alive().get("alive"):
            return {"launched": True, "brave": brave, **cdp_alive()}
    return {"launched": True, "brave": brave, "error": "CDP tidak up dalam 30s",
            "log": str(WORKDIR / "brave_cdp.log")}


def brave_inject(cookies: list[dict], open_url: str, portable: bool = True) -> dict:
    """
    Inject cookie ke Brave via CDP (Playwright connect_over_cdp).
    portable=False -> pakai browser yang sudah jalan (port default).
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"ok": False, "error": f"playwright tidak terpasang: {e}"}

    st = cdp_alive()
    if not st.get("alive"):
        return {"ok": False, "error": "CDP Brave tidak aktif. Panggil /api/brave/launch dulu.",
                "hint": f"curl -X POST http://127.0.0.1:8787/api/brave/launch"}
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{CDP_PORT}")
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            pw = to_playwright(cookies)
            ctx.add_cookies(pw)
            pg = ctx.new_page()
            pg.goto(open_url, wait_until="domcontentloaded", timeout=45000)
            pg.wait_for_timeout(4000)
            title = pg.title()
            # verifikasi via API di dalam browser
            try:
                stxt = pg.evaluate("""async () => (await fetch('/api/auth/session',
                                     {credentials:'include'})).text()""")
            except Exception:
                stxt = None
            return {"ok": True, "injected": len(pw), "url": open_url,
                    "title": title, "session_response": (stxt or "")[:400]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ============================== routes ================================
@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLPage


@app.post("/api/check")
def api_check(body: CookieIn):
    cookies = parse_any(body.raw, body.json_dump)
    if not cookies:
        raise HTTPException(400, "Tidak ada cookie ter-parse (format apapun: Netscape/JSON/header-string/DevTools).")
    fmt_info = sniff_format(body.raw or json.dumps(body.json_dump or {}))
    return JSONResponse({"ok": True, "parsed_count": len(cookies),
                         "format_info": fmt_info,
                         "offline": offline_check(cookies), "live": live_verify(cookies),
                         "urls": build_login_urls(cookies), "ts": int(time.time())})


@app.post("/api/export/bundle")
def export_bundle(body: CookieIn):
    cookies = parse_any(body.raw, body.json_dump)
    if not cookies:
        raise HTTPException(400, "Cookie kosong / gagal parse.")
    urls = build_login_urls(cookies)
    live = live_verify(cookies)
    html = f"""<!doctype html><meta charset=utf-8>
<title>ChatGPT Session Login Bundle</title>
<style>body{{font:14px system-ui;background:#0b0b0b;color:#eee;padding:24px;max-width:900px;margin:auto}}
pre{{background:#111;padding:12px;border-radius:8px;overflow:auto}} .ok{{color:#3fb950}}
.bad{{color:#f85149}} h1{{font-size:20px}}</style>
<h1>ChatGPT Session Login Bundle</h1>
<p>Verdict: <b class="{ 'ok' if live['verdict']=='VALID' else 'bad' }">{live['verdict']}</b>
&mdash; {live['verdict_reason']}</p>
<p>User: <code>{json.dumps(live.get('user'))}</code></p>
<p>Login URL: <a href="{urls['url']}">{urls['url']}</a> |
Session API: <a href="{urls['url_api_session']}">{urls['url_api_session']}</a></p>
<h3>1. Cookie header (curl)</h3><pre>{urls['cookie_header']}</pre>
<h3>2. Cookie JSON (Playwright/extension)</h3><pre>{json.dumps(urls['cookie_json_playwright'], indent=2)}</pre>
<h3>3. Console JS (paste di halaman chatgpt.com)</h3><pre>{urls['bookmarklet_console_js']}</pre>
<h3>4. curl</h3><pre>{urls['curl_session']}</pre>
"""
    return PlainTextResponse(html, media_type="text/html",
                             headers={"Content-Disposition": "attachment; filename=chatgpt_login_bundle.html"})


# -------- batch --------
@app.post("/api/batch")
def api_batch(body: BatchIn):
    items: list[dict] = []
    if body.items:
        items = [{"label": it.get("label") or f"item-{i+1}", "raw": it.get("raw", "")}
                 for i, it in enumerate(body.items)]
    elif (body.raw or "").strip():
        items = split_batch(body.raw)
    if not items:
        raise HTTPException(400, "Batch kosong. Pakai delimiter '=== label ===' atau pisah baris kosong.")

    results: list[dict] = []
    lock = threading.Lock()
    conc = max(1, min(int(body.concurrency or 4), 12))

    def worker(it):
        res = verify_one(it["label"], it.get("raw") or "", it.get("cookies"), it.get("format"))
        with lock:
            results.append(res)
            print(f"[batch] {res['label']:24} {res['verdict']:12} {res.get('user_email')}")

    threads = []
    q = list(items)
    idx = {"i": 0}

    def run():
        while True:
            with lock:
                if idx["i"] >= len(q):
                    return
                it = q[idx["i"]]
                idx["i"] += 1
            worker(it)

    for _ in range(conc):
        t = threading.Thread(target=run, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=600)

    # urutkan sesuai input
    order = {it["label"]: i for i, it in enumerate(items)}
    results.sort(key=lambda r: order.get(r["label"], 999))

    summary = {}
    for r in results:
        summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
    BATCH_STORE.write_text(json.dumps({"ts": int(time.time()), "summary": summary,
                                       "results": results}, indent=2))
    return JSONResponse({"ok": True, "count": len(results), "summary": summary,
                         "results": results, "ts": int(time.time())})


@app.get("/api/batch/export")
def api_batch_export(fmt: str = Query("csv")):
    if not BATCH_STORE.exists():
        raise HTTPException(404, "Belum ada hasil batch.")
    data = json.loads(BATCH_STORE.read_text())
    if fmt == "json":
        return Response(json.dumps(data, indent=2), media_type="application/json",
                        headers={"Content-Disposition": "attachment; filename=batch_results.json"})
    buf = io.StringIO()
    cols = ["label", "verdict", "user_email", "user_name", "user_id", "expires",
            "token_len", "cookie_alive", "cookie_expired", "cookie_count",
            "backend_codes", "device_id", "verdict_reason"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in data["results"]:
        w.writerow(r)
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=batch_results.csv"})


# -------- brave --------
@app.get("/api/brave/status")
def api_brave_status():
    return {"brave_binary": find_brave(), "profile": str(BRAVE_PROFILE),
            "cdp_port": CDP_PORT, "cdp": cdp_alive()}


@app.post("/api/brave/launch")
def api_brave_launch():
    return launch_brave_cdp()


@app.post("/api/brave/inject")
def api_brave_inject(body: BraveInjectIn):
    cookies = parse_any(body.raw, body.json_dump)
    if not cookies:
        raise HTTPException(400, "Cookie kosong / gagal parse.")
    # auto launch kalau belum hidup
    if not cdp_alive().get("alive"):
        launch = launch_brave_cdp()
        if not cdp_alive().get("alive"):
            return JSONResponse({"ok": False, "launch": launch,
                                 "error": "gagal start Brave CDP"}, status_code=500)
    res = brave_inject(cookies, body.open_url, body.portable)
    return JSONResponse(res)


@app.post("/api/brave/kill")
def api_brave_kill():
    try:
        subprocess.run(["pkill", "-f", f"remote-debugging-port={CDP_PORT}"],
                       timeout=10, capture_output=True)
        time.sleep(1)
    except Exception:
        pass
    return {"ok": True, "cdp": cdp_alive()}


# ============================== HTML UI ===============================
HTMLPage = r"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ChatGPT Cookie Validator</title>
<style>
*{box-sizing:border-box} body{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:#0d1117;color:#c9d1d9}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px} .sub{color:#8b949e;margin-bottom:20px}
.tabs{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap}
.tab{padding:8px 16px;background:#21262d;border:1px solid #30363d;border-radius:8px;cursor:pointer;font-weight:600}
.tab.active{background:#238636;border-color:#238636;color:#fff}
.panel{display:none}.panel.active{display:block}
textarea{width:100%;height:240px;background:#010409;color:#c9d1d9;border:1px solid #30363d;
border-radius:8px;padding:12px;font:12px/1.5 ui-monospace,Menlo,monospace;resize:vertical}
.row{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0;align-items:center}
button{background:#238636;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-weight:600;cursor:pointer}
button.alt{background:#21262d;border:1px solid #30363d}
button:hover{filter:brightness(1.12)}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin:14px 0}
.badge{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700;font-size:13px}
.v-VALID{background:#23863633;color:#3fb950;border:1px solid #3fb950}
.v-REVOKED,.v-INVALID,.v-PARSE_ERROR{background:#f8514933;color:#f85149;border:1px solid #f85149}
.v-PARTIAL,.v-DENIED{background:#d2992233;color:#d29922;border:1px solid #d29922}
.v-UNKNOWN,.v-ERROR{background:#8b949e33;color:#8b949e;border:1px solid #8b949e}
table{width:100%;border-collapse:collapse;font-size:12px} th,td{text-align:left;padding:6px 8px;
border-bottom:1px solid #21262d} th{color:#8b949e;font-weight:600}
pre{background:#010409;border:1px solid #30363d;border-radius:8px;padding:12px;overflow:auto;
font:12px ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-all}
.ok{color:#3fb950} .bad{color:#f85149} .warn{color:#d29922}
.st-ALIVE{color:#3fb950}.st-EXPIRED{color:#f85149}.st-SESSION{color:#d29922}
a{color:#58a6ff} .muted{color:#8b949e;font-size:12px}
input[type=number]{background:#010409;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:8px;width:80px}
</style></head>
<body><div class="wrap">
<h1>🍪 ChatGPT Cookie Validator <span class="muted">v2</span></h1>
<div class="sub">Cek cookie valid/expired · generate URL login · batch · auto-login Brave</div>

<div class="tabs">
  <div class="tab active" data-t="single">🔍 Cek Tunggal</div>
  <div class="tab" data-t="batch">📚 Batch</div>
  <div class="tab" data-t="brave">🚀 Auto-Login Brave</div>
</div>

<!-- ===== SINGLE ===== -->
<div class="panel active" id="p-single">
<textarea id="raw" placeholder="Paste cookie format APAPUN — auto-detect:
• Netscape (tab-separated, 7 kolom)
• JSON (array cookie / {cookies:[...]} / {name,value} objek)
• Header string:  a=1; b=2; oai-did=...
• DevTools / EditThisCookie / Cookie-Editor export
• Campur / banyak blok sekaligus (auto-dipisah)

Contoh Netscape:
chatgpt.com	FALSE	/	FALSE	1812869199	oai-hlib	true
.chatgpt.com	TRUE	/	TRUE	1802149501	__Secure-next-auth.session-token.0	PASTE_TOKEN
..."></textarea>
<div class="row">
  <button onclick="check()">🔍 Cek Cookie</button>
  <button class="alt" onclick="document.getElementById('raw').value='';">Bersihkan</button>
  <button class="alt" onclick="loadSample()">Muat Contoh</button>
  <button class="alt" onclick="injectBrave('raw')">🚀 Inject ke Brave</button>
  <button class="alt" id="dl" onclick="download()" disabled>⬇️ Export Bundle</button>
</div>
<div id="out"></div>
</div>

<!-- ===== BATCH ===== -->
<div class="panel" id="p-batch">
<div class="muted">Paste APAPUN (auto-detect): Netscape · JSON · header-string · DevTools · banyak blok campur. Tiap entri dipisah otomatis (=== nama ===, baris kosong, atau blok JSON/netscape berurutan).</div>
<textarea id="rawb" style="height:260px" placeholder="=== akun-1 ===
chatgpt.com	FALSE	/	FALSE	1812869199	oai-hlib	true
.chatgpt.com	TRUE	/	TRUE	1802149501	__Secure-next-auth.session-token.0	....

=== akun-2 ===
[{"name":"oai-did","value":"...","domain":".chatgpt.com"},
 {"name":"__Secure-next-auth.session-token.0","value":"..."}]

akun-3: oai-did=...; oai-hlib=true; __Secure-next-auth.session-token.0=...
(Pisahkan bebas: '=== label ===', baris kosong, atau sequential block — semua auto-kenal)"></textarea>
<div class="row">
  <button onclick="runBatch()">📚 Cek Semua</button>
  <label class="muted">Concurrency <input type="number" id="conc" value="4" min="1" max="12"></label>
  <button class="alt" onclick="downloadBatch('csv')">⬇️ CSV</button>
  <button class="alt" onclick="downloadBatch('json')">⬇️ JSON</button>
</div>
<div id="outb"></div>
</div>

<!-- ===== BRAVE ===== -->
<div class="panel" id="p-brave">
<div class="card">
  <b>Status Brave</b>
  <div class="row"><button class="alt" onclick="braveStatus()">🔄 Refresh Status</button>
  <button class="alt" onclick="braveLaunch()">▶️ Launch Brave CDP</button>
  <button class="alt" onclick="braveKill()">⏹️ Kill Brave CDP</button></div>
  <pre id="bst">-</pre>
</div>
<div class="muted">Paste cookie lalu klik Inject → cookie di-set ke Brave (profil isolasi) + ChatGPT dibuka.</div>
<textarea id="rawr" style="height:200px" placeholder="paste cookie di sini..."></textarea>
<div class="row">
  <button onclick="injectBrave('rawr')">🚀 Inject + Buka ChatGPT</button>
</div>
<div id="outr"></div>
</div>

</div>
<script>
const SAMPLE = `# Netscape HTTP Cookie File
chatgpt.com	FALSE	/	FALSE	1812869199	oai-hlib	true
.chatgpt.com	TRUE	/	FALSE	1812836823	oai-did	7100c66c-8127-4c39-8aea-15a9823d9e0c
.chatgpt.com	TRUE	/	TRUE	1802149501	__Secure-next-auth.session-token.0	PASTE_TOKEN_0
.chatgpt.com	TRUE	/	TRUE	1802149501	__Secure-next-auth.session-token.1	PASTE_TOKEN_1
.chatgpt.com	TRUE	/	TRUE	1794978305	_puid	user-XXXX:1794373504-XXXX
chatgpt.com	FALSE	/	TRUE	1825909504	cf_clearance	PASTE_CF_CLEARANCE`;
function loadSample(){document.getElementById('raw').value=SAMPLE;}
const esc = s => (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));
  t.classList.add('active');
  document.getElementById('p-'+t.dataset.t).classList.add('active');
  if(t.dataset.t==='brave') braveStatus();
});

let lastRaw='';
async function check(){
  const raw=document.getElementById('raw').value.trim();
  if(!raw){alert('Paste cookie dulu');return;}
  lastRaw=raw;
  const out=document.getElementById('out');
  out.innerHTML='<div class="card">⏳ Menguji (session + backend)... ±20s</div>';
  try{
    const r=await fetch('/api/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw})});
    const d=await r.json();
    if(!r.ok){out.innerHTML='<div class="card bad">Error: '+esc(d.detail||JSON.stringify(d))+'</div>';return;}
    render(d); document.getElementById('dl').disabled=false;
  }catch(e){out.innerHTML='<div class="card bad">Gagal: '+esc(e.message)+'</div>';}
}
function render(d){
  const L=d.live,O=d.offline,U=d.urls,u=L.user||{};
  let h=`<div class="card"><div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
    <span class="badge v-${esc(L.verdict)}">${esc(L.verdict)}</span><b>${esc(L.verdict_reason)}</b></div>
    <table>
    <tr><th>Cookie parsed</th><td>${d.parsed_count} (alive ${O.alive} / expired ${O.expired})${d.format_info?' &nbsp;<span class="badge v-VALID" title="'+esc(d.format_info.detail||'')+'">🎯 auto-detect: '+esc(d.format_info.format)+'</span>':' <span class="badge v-PARTIAL">⏳ parsing…</span>'}</td></tr>
    <tr><th>Email</th><td>${esc(u.email)||'<span class=warn>tidak ada</span>'}</td></tr>
    <tr><th>Nama</th><td>${esc(u.name)||'-'}</td></tr>
    <tr><th>User ID</th><td>${esc(u.id)||'-'}</td></tr>
    <tr><th>Session expires</th><td>${esc(L.expires)||'-'}</td></tr>
    <tr><th>Access token</th><td>${L.access_token_len? '<span class=ok>ada ('+L.access_token_len+' chars)</span>':'<span class=bad>tidak ada</span>'}</td></tr>
    <tr><th>Device ID</th><td>${esc(L.device_id)}</td></tr></table></div>`;
  h+='<div class="card"><b>Backend Authorization Test</b><table><tr><th>Endpoint</th><th>Status</th><th>Info</th></tr>';
  (L.backend||[]).forEach(b=>{const okc=b.status===200?'ok':'bad';let info=b.code||b.error||'';
    if(b.models)info='models: '+b.models.join(', ');if(b.plan)info='plan: '+b.plan.join(', ');
    if(b.total!==undefined)info='total: '+b.total;
    h+=`<tr><td>${esc(b.endpoint)}</td><td class="${okc}">${b.status||'-'}</td><td>${esc(info)}</td></tr>`;});
  h+='</table></div>';
  h+='<div class="card"><b>Cookie Detail</b><table><tr><th>Name</th><th>Domain</th><th>Secure</th><th>HttpOnly</th><th>Expiry</th><th>Status</th></tr>';
  O.rows.forEach(c=>{const ex=c.expiry_epoch?new Date(c.expiry_epoch*1000).toISOString().slice(0,10):'-';
    h+=`<tr><td>${esc(c.name)}</td><td>${esc(c.domain)}</td><td>${c.secure?'✔':'✘'}</td><td>${c.httpOnly?'✔':'✘'}</td><td>${ex}</td><td class="st-${c.status}">${c.status}</td></tr>`;});
  h+='</table></div>';
  h+=`<div class="card"><b>🔗 URL Login / Session</b><table>
    <tr><th>Login</th><td><a href="${esc(U.url)}" target="_blank">${esc(U.url)}</a></td></tr>
    <tr><th>Session API</th><td><a href="${esc(U.url_api_session)}" target="_blank">${esc(U.url_api_session)}</a></td></tr></table></div>`;
  h+=`<div class="card"><b>Cookie Header (curl)</b><pre>${esc(U.cookie_header)}</pre></div>`;
  h+=`<div class="card"><b>Cookie JSON (Playwright/extension)</b><pre>${esc(JSON.stringify(U.cookie_json_playwright,null,2))}</pre></div>`;
  h+=`<div class="card"><b>Console JS (paste di halaman chatgpt.com → login)</b><pre>${esc(U.bookmarklet_console_js)}</pre></div>`;
  h+=`<div class="card"><b>curl</b><pre>${esc(U.curl_session)}</pre></div>`;
  document.getElementById('out').innerHTML=h;
}
async function download(){
  const r=await fetch('/api/export/bundle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw:lastRaw})});
  const b=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='chatgpt_login_bundle.html';a.click();
}

// ---- batch ----
async function runBatch(){
  const raw=document.getElementById('rawb').value.trim();
  if(!raw){alert('Paste batch dulu');return;}
  const conc=parseInt(document.getElementById('conc').value||'4');
  const out=document.getElementById('outb');
  out.innerHTML='<div class="card">⏳ Menjalankan batch (concurrency '+conc+')... tunggu</div>';
  try{
    const r=await fetch('/api/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw,concurrency:conc})});
    const d=await r.json();
    if(!r.ok){out.innerHTML='<div class="card bad">Error: '+esc(d.detail||JSON.stringify(d))+'</div>';return;}
    let h='<div class="card"><b>Ringkasan:</b> '+Object.entries(d.summary).map(([k,v])=>`<span class="badge v-${esc(k)}">${esc(k)}: ${v}</span>`).join(' ')+` &nbsp; <span class="muted">(${d.results.length} entri terdeteksi otomatis)</span></div>`;
    h+='<div class="card"><table><tr><th>Label</th><th>Verdict</th><th>Email</th><th>Token</th><th>Alive/Exp</th><th>Backend</th></tr>';
    d.results.forEach(rr=>{h+=`<tr><td>${esc(rr.label)}</td><td><span class="badge v-${esc(rr.verdict)}">${esc(rr.verdict)}</span></td>
      <td>${esc(rr.user_email)||'-'}</td><td>${rr.token_len||0}</td><td>${rr.cookie_alive||0}/${rr.cookie_expired||0}</td><td class="muted">${esc(rr.backend_codes)}</td></tr>`;});
    h+='</table></div>';
    out.innerHTML=h;
  }catch(e){out.innerHTML='<div class="card bad">Gagal: '+esc(e.message)+'</div>';}
}
function downloadBatch(fmt){window.location='/api/batch/export?fmt='+fmt;}

// ---- brave ----
async function braveStatus(){
  try{const r=await fetch('/api/brave/status');const d=await r.json();
    document.getElementById('bst').textContent=JSON.stringify(d,null,2);}catch(e){}
}
async function braveLaunch(){
  document.getElementById('bst').textContent='⏳ launching...';
  try{const r=await fetch('/api/brave/launch',{method:'POST'});const d=await r.json();
    document.getElementById('bst').textContent=JSON.stringify(d,null,2);}catch(e){}
}
async function braveKill(){
  try{const r=await fetch('/api/brave/kill',{method:'POST'});const d=await r.json();
    document.getElementById('bst').textContent=JSON.stringify(d,null,2);}catch(e){}
}
async function injectBrave(id){
  const raw=document.getElementById(id).value.trim();
  if(!raw){alert('Paste cookie dulu');return;}
  const out=document.getElementById(id==='rawr'?'outr':'out');
  const note=document.createElement('div'); note.className='card'; note.textContent='⏳ Inject ke Brave...';
  out.prepend(note);
  try{const r=await fetch('/api/brave/inject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw})});
    const d=await r.json(); note.innerHTML='<b>'+ (d.ok?'✅ Inject OK':'❌ Gagal') +'</b> <pre>'+esc(JSON.stringify(d,null,2))+'</pre>';
  }catch(e){note.innerHTML='<span class="bad">Gagal: '+esc(e.message)+'</span>';}
}
</script></body></html>"""
