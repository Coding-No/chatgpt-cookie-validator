"""
bulk.py — Bulk auto-detector untuk ChatGPT Cookie Validator.

Fitur:
- Terima ZIP (base64 atau upload multipart) berisi banyak file (.txt/.json/.csv/.log/...).
- Terima banyak file sekaligus (multi-upload).
- Terima paste massal (1 blok besar berisi banyak cookie).
- AUTO-DETECT: format per file (Netscape/JSON/header/DevTools), encoding (utf-8/16/latin),
  split multi-akun dalam satu file.
- Nama akun = nama file (tanpa ekstensi) atau label di dalam file.
- Output TERSTRUKTUR: JSON lengkap, CSV, XLSX (kalau openpyxl ada), ringkasan agregat.
- Dedup berdasarkan fingerprint cookie (oai-did / session-token) + user id.
"""

from __future__ import annotations
import base64
import csv
import io
import os
import re
import zipfile
import hashlib
from typing import Any

from auto_parse import auto_parse, sniff_format

# ekstensi yang dianggap file cookie
COOKIE_EXT = {".txt", ".json", ".csv", ".log", ".cookies", ".dump",
              ".tsv", ".env", ".conf", ".text", ""}
SKIP_NAMES = {"readme", "readme.md", "license", ".ds_store", "thumbs.db"}


# ---------------------------------------------------------------- decoding
def _decode_bytes(b: bytes) -> str:
    """Coba beberapa encoding, fallback ke latin-1 (lossless byte->char)."""
    for enc in ("utf-8-sig", "utf-8", "utf-16", "utf-16-le", "cp1252"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("latin-1", errors="replace")


def _is_probably_cookie(text: str) -> bool:
    """Heuristik: apakah isi file memuat cookie/session ChatGPT?"""
    t = text.lower()
    keys = ("oai-did", "session-token", "__secure-next-auth", "oai-hlib",
            "chatgpt.com", "oai-sc", "cf_clearance", "next-auth", "oai-nav-state",
            "name,value", "\"name\"", "cookies")
    if any(k in t for k in keys):
        return True
    # 7 kolom tab-separated (netscape) ?
    for line in text.splitlines()[:40]:
        if line.count("\t") >= 6:
            return True
    return False


# ---------------------------------------------------------------- fingerprint
def _fp(user_id: str | None, cookies: list[dict]) -> str:
    """Fingerprint unik per akun: prioritaskan user_id, lalu oai-did, lalu session-token."""
    seed = ""
    if user_id:
        seed = f"uid:{user_id}"
    else:
        ck = {c["name"]: (c.get("value") or "")[:24] for c in cookies}
        for k in ("oai-did", "__Secure-next-auth.session-token.0",
                  "__Secure-next-auth.session-token", "_puid", "oai-sc"):
            if ck.get(k):
                seed = f"{k}:{ck[k]}"
                break
    if not seed:
        seed = "raw:" + hashlib.sha1(
            "".join(sorted(f"{c['name']}={c.get('value','')}" for c in cookies)).encode()
        ).hexdigest()[:16]
    return hashlib.sha1(seed.encode()).hexdigest()[:16]


# ---------------------------------------------------------------- extraction
def extract_from_zip(zip_bytes: bytes) -> list[dict]:
    """Baca ZIP -> list entri {name, raw, size, fmt_hint}."""
    entries: list[dict] = []
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    for info in zf.infolist():
        if info.is_dir():
            continue
        base = os.path.basename(info.filename)
        if base.lower() in SKIP_NAMES:
            continue
        ext = os.path.splitext(base)[1].lower()
        if ext not in COOKIE_EXT:
            continue
        try:
            raw = _decode_bytes(zf.read(info))
        except Exception:
            continue
        if not raw.strip():
            continue
        label = os.path.splitext(base)[0] or base
        entries.append({"name": label, "raw": raw, "size": len(raw),
                        "source": info.filename,
                        "maybe_cookie": _is_probably_cookie(raw)})
    return entries


def build_batches(entries: list[dict]) -> list[dict]:
    """
    Dari list file mentah -> daftar batch siap-verifikasi.
    Setiap file auto-parse (auto_parse) yang mengembalikan 1+ batch.
    Kalau 1 file memuat banyak akun, jadi banyak batch, label diberi suffix.
    """
    out: list[dict] = []
    for e in entries:
        if not e.get("maybe_cookie", True):
            continue
        try:
            parsed = auto_parse(e["raw"])
        except Exception:
            parsed = []
        if not parsed:
            continue
        # parsed: [{label, cookies, format, detail}, ...]
        n = len(parsed)
        for i, b in enumerate(parsed):
            if not b.get("cookies"):
                continue
            suffix = f"/{i+1}" if n > 1 else ""
            out.append({
                "label": f"{e['name']}{suffix}",
                "cookies": b["cookies"],
                "format": b.get("format"),
                "detail": b.get("detail"),
                "source": e.get("source", e["name"]),
                "cookie_count": len(b["cookies"]),
            })
    return out


# ---------------------------------------------------------------- structuring
def structure_results(results: list[dict]) -> dict:
    """
    Ubah hasil verify (list) -> struktur rapi: dedup, grup verdict, tabel ringkas,
    statistik. Terima 'results' dari main.verify_one.
    """
    # dedup by fingerprint (kalau ada user_id) atau label
    seen: dict[str, dict] = {}
    for r in results:
        key = r.get("fingerprint") or r.get("user_id") or r.get("label")
        if key and key in seen:
            seen[key]["duplicate_of"] = seen[key].get("label")
            seen[key].setdefault("duplicates", []).append(r.get("label"))
            continue
        if key:
            seen[key] = r
    rows = list(seen.values())

    by_verdict: dict[str, int] = {}
    by_format: dict[str, int] = {}
    for r in rows:
        v = r.get("verdict", "UNKNOWN")
        by_verdict[v] = by_verdict.get(v, 0) + 1
        f = r.get("format") or "unknown"
        by_format[f] = by_format.get(f, 0) + 1

    # tabel ringkas untuk display
    table = []
    for r in rows:
        u = r.get("user") or {}
        table.append({
            "label": r.get("label"),
            "verdict": r.get("verdict"),
            "email": u.get("email") or "",
            "name": u.get("name") or "",
            "user_id": u.get("id") or "",
            "plan": (r.get("account") or {}).get("plan") or "",
            "format": r.get("format") or "",
            "cookies": r.get("parsed_count") or r.get("cookie_count") or 0,
            "expires": r.get("expires") or "",
            "source": r.get("source") or "",
            "note": r.get("verdict_reason") or "",
        })
    # urut: VALID dulu, lalu REVOKED/PARTIAL/INVALID
    order = {"VALID": 0, "PARTIAL": 1, "REVOKED": 2, "INVALID": 3, "DENIED": 4,
             "PARSE_ERROR": 5, "UNKNOWN": 6}
    table.sort(key=lambda x: (order.get(x["verdict"], 9), x["label"] or ""))

    return {
        "total_files": len(results),
        "total_unique": len(rows),
        "duplicates": len(results) - len(rows),
        "by_verdict": by_verdict,
        "by_format": by_format,
        "table": table,
        "valid_accounts": [t for t in table if t["verdict"] == "VALID"],
        "results": rows,
    }


# ---------------------------------------------------------------- exporters
def to_csv(structured: dict) -> str:
    buf = io.StringIO()
    cols = ["label", "verdict", "email", "name", "user_id", "plan",
            "format", "cookies", "expires", "source", "note"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for row in structured["table"]:
        w.writerow(row)
    return buf.getvalue()


def to_xlsx(structured: dict) -> bytes | None:
    try:
        from openpyxl import Workbook
    except Exception:
        return None
    wb = Workbook()
    ws = wb.active
    ws.title = "Accounts"
    cols = ["label", "verdict", "email", "name", "user_id", "plan",
            "format", "cookies", "expires", "source", "note"]
    ws.append([c.upper() for c in cols])
    for row in structured["table"]:
        ws.append([row.get(c, "") for c in cols])
    # sheet ringkasan
    ws2 = wb.create_sheet("Summary")
    ws2.append(["Metric", "Value"])
    ws2.append(["Total files", structured["total_files"]])
    ws2.append(["Unique accounts", structured["total_unique"]])
    ws2.append(["Duplicates", structured["duplicates"]])
    for k, v in structured["by_verdict"].items():
        ws2.append([f"verdict:{k}", v])
    for k, v in structured["by_format"].items():
        ws2.append([f"format:{k}", v])
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def to_json(structured: dict) -> str:
    import json
    # buang field berat (rows/cookies mentah) biar ringan tapi tetap informatif
    light = {
        "summary": {
            "total_files": structured["total_files"],
            "total_unique": structured["total_unique"],
            "duplicates": structured["duplicates"],
            "by_verdict": structured["by_verdict"],
            "by_format": structured["by_format"],
        },
        "accounts": structured["table"],
        "valid": [t["label"] for t in structured["valid_accounts"]],
    }
    return json.dumps(light, indent=2, ensure_ascii=False)
