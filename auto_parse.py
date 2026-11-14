"""
auto_parse.py — Multi-format cookie input auto-detector & normalizer.

Tujuan: user paste APAPUN, sistem deteksi sendiri format + jumlah entry,
tanpa perlu tahu/memilih format. Toleran terhadap:
  - Netscape / cookies.txt (tab-separated, 7 kolom)
  - Netscape dengan #HttpOnly_ prefix
  - Netscape spasi-separated (beberapa dump pakai spasi)
  - JSON array  [{...}, {...}]
  - JSON object {"cookies":[...]}   (Playwright/Cookie-Editor storageState)
  - JSON object {"name":..,"value":..}  (single)
  - Cookie request header string  "a=1; b=2; c=3"
  - Set-Cookie header lines       "Set-Cookie: name=value; Domain=..."
  - document.cookie string
  - Raw lines  "name=value"  (uno)
  - Chrome "Copy as cURL" / curl command (ambil -b / --cookie / -H 'cookie:')
  - Multiple batches dipisah separator:  '=== label ===', '--- label ---',
    blank-line blocks, atau comment '# label'
  - Mixed: sebagian Netscape + sebagian JSON dalam 1 paste

Output: list of batches ->
    [{"label": str, "format": str, "cookies": [ {name,value,domain,path,
       secure,httpOnly,expirationDate}, ... ]}, ...]

Dipakai oleh /api/check (amball batch pertama) dan /api/batch (semua batch).
"""

from __future__ import annotations
import json
import re
from typing import Any

# ---------- konstanta ----------
NS_COLS = 7
HTTPONLY_PREFIX = "#HttpOnly_"

# separator batch: '=== label ===', '--- label ---', '### label', '// label'
BATCH_SEP = re.compile(
    r'^\s*(?:=+|-{2,}|#{2,}|\*{2,}|\/{2,})\s*(?P<label>[^=\-\#\*\/].*?)\s*(?:=+|-{2,}|\*{2,})?\s*$'
)

# pola baris yang kelihatan seperti baris cookie (untuk grouping blok)
LOOKS_LIKE_COOKIE = re.compile(
    r'(?:'                       # netscape baris (domain + tab) ATAU
    r'^\.?[A-Za-z0-9_.\-]+\s*[\t ]+(?:TRUE|FALSE)\s*[\t ]+/'  # netscape
    r'|[A-Za-z0-9_\-\.%\$\{\}]{1,80}\s*=\s*[^=;]{0,4000}(?:;|$)'  # name=value
    r'|^\s*Set-Cookie\s*:'       # set-cookie
    r')',
    re.IGNORECASE,
)


# ============================================================
# 1. DETEKSI FORMAT
# ============================================================
def sniff_format(text: str) -> str:
    """Tebak format dominan dari potongan teks. Return: 'json'|'netscape'|'header'|'raw'|'empty'."""
    t = text.strip()
    if not t:
        return "empty"
    # JSON?
    if t[0] in "[{":
        try:
            json.loads(t)
            return "json"
        except Exception:
            pass
    # cookie header / document.cookie "a=b; c=d"
    first = t.splitlines()[0].strip()
    if re.match(r'^\s*(?:cookie|set-cookie)\s*:', first, re.I):
        return "header"
    if "=" in first and ";" in first and "\t" not in first and not first.startswith("#"):
        # heuristik header: banyak 'name=value;'
        if len(re.findall(r'[^=;\s]+\s*=\s*[^;=]*', first)) >= 2:
            return "header"
    # netscape dominan?
    ns = sum(1 for l in t.splitlines() if l.count("\t") >= 6 or _is_netscape_row(l))
    if ns > 0:
        return "netscape"
    # raw name=value
    if re.match(r'^[A-Za-z0-9_\-\.]+\s*=', first):
        return "raw"
    return "raw"


def _is_netscape_row(line: str) -> bool:
    p = line.lstrip(HTTPONLY_PREFIX).split("\t")
    if len(p) < NS_COLS:
        p = line.lstrip(HTTPONLY_PREFIX).split()
    return len(p) >= NS_COLS and p[1].upper() in ("TRUE", "FALSE") and p[2].startswith("/")


# ============================================================
# 2. PARSER PER-FORMAT
# ============================================================
def _mk(name, value, domain=".chatgpt.com", path="/", secure=True,
        httpOnly=False, exp=0, sameSite="Lax") -> dict:
    c = {"name": name, "value": value, "domain": domain, "path": path,
         "secure": bool(secure), "httpOnly": bool(httpOnly), "sameSite": sameSite}
    if exp:
        c["expirationDate"] = int(exp)
    return c


def parse_netscape(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        if line.startswith("#") and not line.startswith(HTTPONLY_PREFIX):
            continue
        http_only = False
        if line.startswith(HTTPONLY_PREFIX):
            http_only = True
            line = line[len(HTTPONLY_PREFIX):]
        # tab dulu; fallback split whitespace >= 7 kolom
        parts = line.split("\t")
        if len(parts) < NS_COLS:
            parts = line.split()
        if len(parts) < NS_COLS:
            continue
        dom, sub, path, secure, exp, name, *rest = parts
        val = "\t".join(rest) if len(rest) > 1 else (rest[0] if rest else "")
        try:
            e = int(exp)
        except ValueError:
            e = 0
        out.append(_mk(name, val, dom, path or "/", secure.upper() == "TRUE",
                       http_only, e))
    return out


def parse_json(text: str) -> list[dict]:
    data = json.loads(text)
    return _from_json_obj(data)


def _from_json_obj(data: Any) -> list[dict]:
    # unwrap umum
    if isinstance(data, dict):
        for k in ("cookies", "Cookies", "data", "items", "cookies_list"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
        else:
            if "name" in data and "value" in data:
                data = [data]
            else:
                # flat dict {"oai-did":"...", "oai-hlib":"true", ...} -> list cookie
                flat = []
                for k, v in data.items():
                    if isinstance(v, (str, int, float, bool)) and k and not k.startswith("_"):
                        flat.append({"name": str(k), "value": str(v)})
                data = flat if flat else [data]
    if not isinstance(data, list):
        return []
    out = []
    for c in data:
        if not isinstance(c, dict):
            continue
        name = c.get("name") or c.get("Name") or c.get("key")
        if not name:
            continue
        val = c.get("value", c.get("Value", ""))
        dom = c.get("domain") or c.get("Domain") or ".chatgpt.com"
        path = c.get("path") or c.get("Path") or "/"
        secure = c.get("secure", c.get("Secure", True))
        ho = c.get("httpOnly", c.get("HttpOnly", c.get("httponly", False)))
        exp = (c.get("expirationDate") or c.get("expires") or c.get("expiry")
               or c.get("Expires") or 0)
        try:
            exp = int(float(exp))
        except Exception:
            exp = 0
        ss = c.get("sameSite") or c.get("SameSite") or "Lax"
        out.append(_mk(name, str(val), str(dom), str(path), secure, ho, exp, ss))
    return out


def parse_header(text: str) -> list[dict]:
    """'a=1; b=2; c=3'  atau baris Set-Cookie/Cookie."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        line = re.sub(r'^(?:cookie|set-cookie)\s*:\s*', '', line, flags=re.I)
        # attribut set-cookie dipisah ';'
        for seg in line.split(";"):
            seg = seg.strip()
            if not seg or "=" not in seg:
                continue
            k, _, v = seg.partition("=")
            k, v = k.strip(), v.strip()
            kl = k.lower()
            # skip attribut cookie
            if kl in ("domain", "path", "expires", "max-age", "samesite",
                      "secure", "httponly", "version", "comment"):
                continue
            if not k:
                continue
            out.append(_mk(k, v))
    return out


def parse_raw_pairs(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip().rstrip(";")
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k:
            out.append(_mk(k, v))
    return out


def parse_curl(text: str) -> list[dict]:
    """Ambil cookie dari command 'Copy as cURL'."""
    m = re.search(r"(?:-b|--cookie)\s+(['\"])(.*?)\1", text, re.S)
    if not m:
        m = re.search(r"-H\s+(['\"])cookie:\s*(.*?)\1", text, re.S | re.I)
    if not m:
        return []
    return parse_header(m.group(2))


# ============================================================
# 3. SPLIT BATCH / MULTI-ENTRY
# ============================================================
def split_batches(text: str) -> list[tuple[str, str]]:
    """Bagi paste jadi [(label, body)]. Deteksi separator; fallback blok kosong."""
    lines = text.splitlines()
    batches: list[tuple[str, str]] = []
    cur_label, cur_lines = None, []

    def flush():
        nonlocal cur_label, cur_lines
        body = "\n".join(cur_lines).strip()
        if body:
            batches.append((cur_label or f"entry-{len(batches)+1}", body))
        cur_lines = []

    for ln in lines:
        m = BATCH_SEP.match(ln)
        if m and not ln.strip().startswith("#HttpOnly_"):
            label = m.group("label").strip() or f"entry-{len(batches)+1}"
            # separator '=== label ==='
            flush()
            cur_label = label
        else:
            cur_lines.append(ln)
    flush()

    if len(batches) <= 1:
        # coba pisah per blok kosong (>=1 baris kosong), hanya bila tiap blok
        # punya pola cookie sendiri
        blocks = re.split(r"\n\s*\n", text.strip())
        if len(blocks) > 1 and all(_block_looks_cookie(b) for b in blocks):
            return [(f"entry-{i+1}", b.strip()) for i, b in enumerate(blocks)
                    if b.strip()]
    return batches


def _block_looks_cookie(b: str) -> bool:
    b = b.strip()
    if not b:
        return False
    if b[0] in "[{":
        return True
    if re.search(r'(?:set-cookie|cookie)\s*:', b, re.I):
        return True
    if any(_is_netscape_row(l) for l in b.splitlines()):
        return True
    # header 1-baris banyak pasangan
    return bool(re.match(r'^[^=;\s]+\s*=\s*[^;]+(?:;\s*[^=;\s]+\s*=[^;]+)+', b))


# ============================================================
# 4. ENTRY POINT: AUTO-DETECT PARSE
# ============================================================
def auto_parse(text: str) -> list[dict]:
    """
    Terima APAPUN. Return list batch:
      [{"label","format","cookies":[...]}]
    """
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return []

    # JSON utuh (single object/array) -> 1 batch
    stripped = text.strip()
    if stripped[0] in "[{":
        try:
            data = json.loads(stripped)
            cks = _from_json_obj(data)
            if cks:
                return [{"label": "json-input", "format": "json", "cookies": cks}]
        except Exception:
            pass

    # curl command
    if re.search(r'\bcurl\b', text, re.I) and re.search(r'-b|--cookie|cookie:', text, re.I):
        cks = parse_curl(text)
        if cks:
            return [{"label": "curl-input", "format": "curl", "cookies": cks}]

    batches = split_batches(text)
    out: list[dict] = []
    for label, body in batches:
        # jika blok ini ada baris netscape -> parse netscape untuk baris netscape,
        # dan parse sisanya sebagai header/raw (mixed tolerant)
        fmt = sniff_format(body)
        cks: list[dict] = []
        if fmt == "json":
            try:
                cks = _from_json_obj(json.loads(body))
            except Exception:
                cks = []
        elif fmt == "netscape":
            cks = parse_netscape(body)
            # tambahan: baris non-netscape yang mirip 'name=value'
            if not cks:
                cks = parse_header(body) or parse_raw_pairs(body)
        elif fmt == "header":
            cks = parse_header(body)
        else:
            cks = parse_netscape(body) or parse_header(body) or parse_raw_pairs(body)
        # dedupe by name (last wins)
        seen: dict[str, dict] = {}
        for c in cks:
            seen[c["name"]] = c
        cks = list(seen.values())
        if cks:
            out.append({"label": label, "format": fmt, "cookies": cks})
    return out
