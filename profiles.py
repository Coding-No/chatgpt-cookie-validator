"""
profiles.py — Profile Manager: 1 akun ChatGPT = 1 profil Brave terpisah.

Konsep:
- Tiap akun disimpan di PROFILES_DIR/<slug>/
    ├── profile/            ← user-data-dir Brave (cookie tersimpan permanen)
    ├── cookies.json        ← cookie asli (backup, Playwright format)
    ├── meta.json           ← email, verdict, device_id, waktu
- Launch: buka Brave baru dengan --user-data-dir=profil itu (+ CDP port unik).
  Karena cookie udah nempel di profil, Brave langsung login — nggak perlu inject ulang.
- Dashboard: halaman HTML buat lihat semua akun + tombol "Buka" sekali klik.

Catatan teknis:
- Brave di mesin ini = flatpak (com.brave.Browser). Launch = `flatpak run com.brave.Browser --args ...`
- Port CDP unik per profil (mulai 9222) biar bisa banyak akun jalan bareng.
- Mode headless tersedia; default: GUI (kalau DISPLAY ada). Fallback: headless.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import re
from pathlib import Path

PROFILES_DIR = Path(os.environ.get("PROFILES_DIR", "/tmp/cgpt_profiles"))
BRAVE_APP_ID = "com.brave.Browser"
CDP_BASE = int(os.environ.get("CDP_BASE", "9222"))


# ------------------------------------------------------------------ utils
def _slug(email: str, user_id: str | None = None) -> str:
    base = (email or user_id or "unknown").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", base).strip("_") or "account"
    if user_id:
        s += "_" + re.sub(r"[^a-zA-Z0-9]", "", user_id)[-6:]
    return s[:80]


def _brave_cmd(profile_dir: Path, cdp_port: int, headless: bool, extra: list[str] | None = None) -> list[str]:
    """Bangun perintah launch Brave (flatpak / native)."""
    common = [
        f"--user-data-dir={profile_dir}",
        f"--remote-debugging-port={cdp_port}",
        "--remote-allow-origins=*",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-blink-features=AutomationControlled",
        "--disable-features=Translate,OptimizationHints",
        "--window-size=1280,860",
    ]
    if headless:
        common.insert(3, "--headless=new")
        common.append("--no-sandbox")
        common.append("--disable-gpu")
    # PENTING: headless hanya boleh 1 URL — gabung about:blank + target
    if extra:
        common += extra
    else:
        common.append("about:blank")
    # deteksi binary
    native = shutil.which("brave-browser") or shutil.which("brave")
    if native:
        base = [native] + common
    else:
        base = ["flatpak", "run", BRAVE_APP_ID, "--args"] + common
    # di service systemd, flatpak butuh session D-Bus → bungkus dgn dbus-run-session
    return base


def _env_for_brave() -> dict:
    """Env yang dibutuhkan flatpak/Brave saat dijalankan dari service systemd."""
    env = dict(os.environ)
    uid = os.getuid()
    xdg = env.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
    env["XDG_RUNTIME_DIR"] = xdg
    bus = Path(xdg) / "bus"
    if bus.exists():
        env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus}")
    env.setdefault("HOME", str(Path.home()))
    # kalau ada DISPLAY/WAYLAND di sistem user, warisi (GUI mode)
    if not env.get("DISPLAY") and not env.get("WAYLAND_DISPLAY"):
        d = Path("/tmp/.X11-unix")
        if d.exists():
            xs = sorted(d.glob("X*"))
            if xs:
                env["DISPLAY"] = ":" + xs[-1].name[1:]
    return env



# --------------------------------------------------------------- profiles
def list_profiles() -> list[dict]:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    for d in sorted(PROFILES_DIR.iterdir()):
        meta_p = d / "meta.json"
        if not meta_p.exists():
            continue
        try:
            meta = json.loads(meta_p.read_text())
        except Exception:
            continue
        meta["slug"] = d.name
        meta["dir"] = str(d)
        meta["has_profile"] = (d / "profile").exists()
        meta["cookie_count"] = len(_load_cookies(d))
        meta["running"] = _is_running(meta.get("cdp_port"))
        out.append(meta)
    return out


def _load_cookies(d: Path) -> list[dict]:
    p = d / "cookies.json"
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text()).get("cookies", [])
    except Exception:
        return []


def _next_port() -> int:
    used = set()
    for d in PROFILES_DIR.glob("*/meta.json"):
        try:
            used.add(int(json.loads(d.read_text()).get("cdp_port") or 0))
        except Exception:
            pass
    p = CDP_BASE
    while p in used:
        p += 1
    return p


def _is_running(port) -> bool:
    if not port:
        return False
    try:
        import requests
        r = requests.get(f"http://127.0.0.1:{int(port)}/json/version", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def add_profile(email: str, cookies: list[dict], verdict: str = "", user_id: str = "",
                expires: str = "", device_id: str = "", open_now: bool = False) -> dict:
    """Simpan akun baru dari cookie (Playwright format). Return meta."""
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    slug = _slug(email, user_id)
    d = PROFILES_DIR / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "profile").mkdir(exist_ok=True)
    # simpan cookie asli (backup)
    (d / "cookies.json").write_text(json.dumps(
        {"email": email, "cookies": cookies}, indent=2))
    meta_p = d / "meta.json"
    meta = {}
    if meta_p.exists():
        try:
            meta = json.loads(meta_p.read_text())
        except Exception:
            meta = {}
    meta.update({
        "email": email, "verdict": verdict, "user_id": user_id,
        "expires": expires, "device_id": device_id,
        "cookie_count": len(cookies),
        "cdp_port": meta.get("cdp_port") or _next_port(),
        "created": meta.get("created") or int(time.time()),
        "updated": int(time.time()),
    })
    meta_p.write_text(json.dumps(meta, indent=2))
    res = {"ok": True, "slug": slug, "dir": str(d), **meta}
    if open_now:
        res["launch"] = launch_profile(slug)
    return res


def launch_profile(slug: str, headless: bool = False, url: str = "https://chatgpt.com/") -> dict:
    """
    Buka Brave dengan profil akun ini + inject cookie (sekali) supaya pasti login.
    Kalau profil sudah pernah dibuka, cookie udah nempel → langsung login.
    """
    d = PROFILES_DIR / slug
    meta_p = d / "meta.json"
    if not meta_p.exists():
        return {"ok": False, "error": f"profil '{slug}' tidak ada"}
    meta = json.loads(meta_p.read_text())
    port = int(meta.get("cdp_port") or _next_port())
    profile_dir = d / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    if _is_running(port):
        return {"ok": True, "already": True, "cdp_port": port,
                "url": f"http://127.0.0.1:{port}/json/version", "slug": slug}

    # mode GUI kalau ada DISPLAY, else headless
    env = _env_for_brave()
    use_headless = headless or not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))
    cmd = _brave_cmd(profile_dir, port, use_headless, extra=[url])
    log = open(d / "brave.log", "ab")
    if cmd and cmd[0] == "flatpak" and not env.get("DBUS_SESSION_BUS_ADDRESS"):
        cmd = ["dbus-run-session", "--"] + cmd
    subprocess.Popen(cmd, stdout=log, stderr=log, start_new_session=True, env=env)

    # tunggu CDP up
    ok = False
    for _ in range(25):
        time.sleep(1.2)
        if _is_running(port):
            ok = True
            break
    if not ok:
        return {"ok": False, "error": "CDP tidak up dalam 30s", "cmd": " ".join(cmd),
                "log": str(d / "brave.log"), "slug": slug}

    # inject cookie biar pasti login (sekali; kalau udah ada, tetap aman)
    inj = {"injected": 0}
    try:
        cks = _load_cookies(d)
        if cks:
            inj = _inject_cdp(port, cks)
    except Exception as e:
        inj = {"error": str(e)}

    return {"ok": True, "slug": slug, "email": meta.get("email"), "cdp_port": port,
            "headless": use_headless, "injected": inj.get("injected", 0),
            "inject_error": inj.get("error"), "url": url,
            "cdp": f"http://127.0.0.1:{port}/json/version"}


def _inject_cdp(port: int, cookies: list[dict]) -> dict:
    """Set cookie via CDP (Playwright connect_over_cdp)."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"injected": 0, "error": f"playwright: {e}"}
    pw_cookies = []
    for c in cookies:
        pc = {"name": c.get("name"), "value": c.get("value"),
              "domain": c.get("domain") or ".chatgpt.com",
              "path": c.get("path") or "/"}
        if c.get("secure") is not None:
            pc["secure"] = bool(c["secure"])
        if c.get("httpOnly") is not None:
            pc["httpOnly"] = bool(c["httpOnly"])
        # expiry WAJIB > now, else cookie dibuang browser
        exp = c.get("expiry_epoch") or c.get("expires")
        try:
            if exp and int(exp) > time.time():
                pc["expires"] = int(exp)
        except Exception:
            pass
        pw_cookies.append(pc)
    try:
        with sync_playwright() as p:
            b = p.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
            ctx = b.contexts[0] if b.contexts else b.new_context()
            ctx.add_cookies(pw_cookies)
            return {"injected": len(pw_cookies)}
    except Exception as e:
        return {"injected": 0, "error": str(e)}


def kill_profile(slug: str) -> dict:
    d = PROFILES_DIR / slug
    meta_p = d / "meta.json"
    if not meta_p.exists():
        return {"ok": False, "error": "profil tidak ada"}
    meta = json.loads(meta_p.read_text())
    port = meta.get("cdp_port")
    try:
        subprocess.run(["pkill", "-f", f"user-data-dir={d/'profile'}"], timeout=10,
                       capture_output=True)
        time.sleep(0.6)
    except Exception:
        pass
    return {"ok": True, "slug": slug, "running": _is_running(port)}


def delete_profile(slug: str) -> dict:
    d = PROFILES_DIR / slug
    if not d.exists():
        return {"ok": False, "error": "profil tidak ada"}
    rr = kill_profile(slug)
    time.sleep(0.6)
    try:
        shutil.rmtree(d, ignore_errors=True)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "slug": slug, "deleted": True}


def import_from_bulk(only_verdicts: tuple[str, ...] = ("VALID", "PARTIAL"),
                     limit: int | None = None) -> dict:
    """
    Ambil hasil scan bulk terakhir (bulk_last.json), bikin profil buat tiap
    akun yang vitdict-nya di only_verdicts.
    """
    store = Path(os.environ.get("BULK_STORE", "/home/nopauwxp/.hermes/workspace/x410_cookies/app/bulk_last.json"))
    if not store.exists():
        return {"ok": False, "error": "belum ada hasil bulk (bulk_last.json)"}
    data = json.loads(store.read_text())
    want = {v.upper() for v in only_verdicts}
    created, skipped = [], []
    n = 0
    for r in data.get("results", []):
        if (r.get("verdict") or "").upper() not in want:
            continue
        if not r.get("cookies"):
            skipped.append({"email": r.get("user_email"), "reason": "no raw cookie"})
            continue
        if limit and n >= limit:
            break
        res = add_profile(email=r.get("user_email") or "", cookies=r.get("cookies") or [],
                           verdict=r.get("verdict") or "", user_id=r.get("user_id") or "",
                           expires=r.get("expires") or "", device_id=r.get("device_id") or "")
        created.append({"email": res.get("email"), "slug": res.get("slug"),
                        "cookie_count": res.get("cookie_count")})
        n += 1
    return {"ok": True, "created": len(created), "profiles": created, "skipped": skipped}


def launch_all(verdicts: tuple[str, ...] = ("VALID",), headless: bool = False,
               stagger: float = 2.0, max_launch: int = 8) -> dict:
    """
    Buka banyak akun sekaligus (jendela/jendela headless terpisah).
    Karena tiap profil = proses Brave sendiri, bisa jalan bareng.
    """
    launched = []
    for i, m in enumerate(list_profiles()):
        if (m.get("verdict") or "").upper() not in {v.upper() for v in verdicts}:
            continue
        if len(launched) >= max_launch:
            break
        r = launch_profile(m["slug"], headless=headless)
        launched.append({"email": m.get("email"), "slug": m["slug"], "ok": r.get("ok"),
                         "cdp_port": r.get("cdp_port")})
        time.sleep(stagger)
    return {"ok": True, "launched": len(launched), "details": launched}


def dashboard_html(base_url: str = "") -> str:
    """Halaman dashboard pilih-akun sekali klik."""
    return DASH_HTML.replace("{{BASE}}", base_url)


DASH_HTML = r"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>🧑‍💻 Profile Manager — banyak akun</title>
<style>
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#c9d1d9}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#8b949e;margin-bottom:16px}
.row{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0;align-items:center}
button{background:#238636;color:#fff;border:0;border-radius:8px;padding:9px 16px;font-weight:600;cursor:pointer}
button.alt{background:#21262d;border:1px solid #30363d}button.red{background:#da3633}
button:hover{filter:brightness(1.12)}button:disabled{opacity:.5;cursor:not-allowed}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px;margin:12px 0}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:700;font-size:12px}
.v-VALID{background:#23863633;color:#3fb950;border:1px solid #3fb950}
.v-REVOKED,.v-INVALID{background:#f8514933;color:#f85149;border:1px solid #f85149}
.v-PARTIAL{background:#d2992233;color:#d29922;border:1px solid #d29922}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px;border-bottom:1px solid #21262d}
th{color:#8b949e}pre{background:#010409;border:1px solid #30363d;border-radius:8px;padding:10px;overflow:auto;font:12px ui-monospace,monospace}
.ok{color:#3fb950}.bad{color:#f85149}.warn{color:#d29922}.muted{color:#8b949e;font-size:12px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.dot.on{background:#3fb950;box-shadow:0 0 6px #3fb950}.dot.off{background:#484f58}
</style></head><body><div class="wrap">
<h1>🧑‍💻 Profile Manager</h1>
<div class="sub">1 akun = 1 profil Brave terpisah (cookie nempel permanen) → buka sekali klik, login otomatis.</div>

<div class="row">
  <button onclick="importBulk()">📥 Import dari hasil scan (VALID+PARTIAL)</button>
  <button class="alt" onclick="launchAll('VALID')">▶️ Buka semua yg VALID</button>
  <button class="alt" onclick="load()">🔄 Refresh</button>
</div>
<div class="muted">base: <code>{{BASE}}</code></div>
<div id="msg" class="muted"></div>
<div id="list"></div>
</div>
<script>
const BASE='{{BASE}}';
const esc=s=>(s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function load(){
  const r=await fetch(BASE+'/api/profiles');const d=await r.json();
  let h='<div class="card"><b>📋 '+d.count+' akun tersimpan</b> <span class="muted">(profiles: '+d.dir+')</span>';
  if(!d.count){h+='<div class="muted" style="margin-top:8px">Belum ada. Klik "Import dari hasil scan" dulu.</div>';}
  else{
    h+='<table><tr><th>Status</th><th>Email</th><th>Verdict</th><th>Cookie</th><th>Expires</th><th>Aksi</th></tr>';
    d.profiles.forEach(p=>{
      h+='<tr><td><span class="dot '+(p.running?'on':'off')+'"></span>'+(p.running?'jalan':'mati')+'</td>'
        +'<td>'+esc(p.email||'-')+'</td>'
        +'<td><span class="badge v-'+esc(p.verdict)+'">'+esc(p.verdict||'-')+'</span></td>'
        +'<td>'+p.cookie_count+'</td><td class="muted">'+esc(p.expires||'-')+'</td>'
        +'<td><button onclick="open1(\''+p.slug+'\')">▶️ Buka</button> '
        +'<button class="alt" onclick="open1(\''+p.slug+'\',true)">🕶️ Headless</button> '
        +'<button class="red" onclick="kill1(\''+p.slug+'\')">⏹️</button> '
        +'<button class="red" onclick="del1(\''+p.slug+'\')">🗑️</button></td></tr>';
    });
    h+='</table>';
  }
  h+='</div>';
  document.getElementById('list').innerHTML=h;
}
async function importBulk(){
  msg('⏳ Import dari hasil scan terakhir...');
  const r=await fetch(BASE+'/api/profiles/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({only:['VALID','PARTIAL']})});
  const d=await r.json();msg(d.ok?'✅ '+d.created+' profil dibuat':'❌ '+(d.error||''));load();
}
async function launchAll(v){
  msg('⏳ Buka semua ('+v+')...');
  const r=await fetch(BASE+'/api/profiles/launch_all',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({verdicts:[v],headless:false})});
  const d=await r.json();msg('✅ '+d.launched+' akun dibuka');load();
}
async function open1(slug,hl){
  msg('⏳ Buka '+slug+'...');
  const r=await fetch(BASE+'/api/profiles/'+slug+'/launch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({headless:!!hl})});
  const d=await r.json();
  msg(d.ok?('✅ '+(d.email||slug)+' terbuka (CDP '+d.cdp_port+')'):('❌ '+(d.error||'')));
  load();
}
async function kill1(slug){await fetch(BASE+'/api/profiles/'+slug+'/kill',{method:'POST'});load();}
async function del1(slug){if(!confirm('Hapus profil '+slug+'?'))return;await fetch(BASE+'/api/profiles/'+slug,{method:'DELETE'});load();}
function msg(t){document.getElementById('msg').textContent=t;}
load();
</script></body></html>"""
