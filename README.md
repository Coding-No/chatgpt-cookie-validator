# 🍪 ChatGPT Cookie Validator

Cek cepat: **cookie ChatGPT masih hidup atau sudah expired/revoked** — lalu generate bahan login (URL, header, JSON, console JS) dan opsi auto-login ke Brave.

## Fitur

- **Cek tunggal** — paste dump cookie (Netscape) atau JSON → verdict: `VALID` / `REVOKED` / `INVALID` / `PARTIAL` / `DENIED`
- **Backend test** — verifikasi nyata ke `/backend-api/me`, `/models`, `/accounts/check`, `/conversations` (bukan cuma `/api/auth/session`)
- **Generate URL login** — login URL, session API URL, cookie header (curl), cookie JSON (Playwright/ekstensi), console JS
- **Export Bundle** — download HTML berisi semua bahan login
- **Batch mode** — paste banyak cookie sekaligus → cek paralel → export CSV/JSON
- **Auto-login Brave** — inject cookie ke Brave (via CDP, profil isolasi) + buka ChatGPT

## Install & Jalankan

```bash
git clone https://github.com/Coding-No/<repo>.git
cd <repo>
./run.sh
```

Buka `http://127.0.0.1:8787`

### Akses dari device lain / VPS (endpoint publik)

```bash
./run.sh --host 0.0.0.0 --port 8787
# atau
HOST=0.0.0.0 PORT=8787 ./run.sh
```

## Manual (tanpa run.sh)

```bash
python3 -m pip install -r requirements.txt
python3 -m uvicorn main:app --host 127.0.0.1 --port 8787
```

## API

| Method | Endpoint | Fungsi |
|---|---|---|
| GET | `/` | UI web |
| GET | `/docs` | OpenAPI docs |
| POST | `/api/check` | Validasi + verdict + URL. Body: `{"raw":"<dump>"}` |
| POST | `/api/export/bundle` | Download HTML login bundle |
| POST | `/api/batch` | Batch cek. Body: `{"raw":"...","concurrency":4}` |
| GET | `/api/batch/export?fmt=csv\|json` | Unduh hasil batch terakhir |
| GET | `/api/brave/status` | Status Brave + CDP |
| POST | `/api/brave/launch` | Launch Brave dengan CDP |
| POST | `/api/brave/inject` | Inject cookie + buka ChatGPT |
| POST | `/api/brave/kill` | Matikan Brave CDP |

### Contoh curl

```bash
# cek satu
curl -s -X POST http://127.0.0.1:8787/api/check \
  -H 'Content-Type: application/json' \
  -d '{"raw":"chatgpt.com\tFALSE\t/\tTRUE\t1802149501\t__Secure-next-auth.session-token.0\tTOKEN"}' \
  | jq '{verdict:.live.verdict, email:.live.user.email}'

# batch (pisah '=== label ===')
curl -s -X POST http://127.0.0.1:8787/api/batch \
  -H 'Content-Type: application/json' \
  -d '{"raw":"=== a ===\n<cookie>\n\n=== b ===\n<cookie>","concurrency":4}' | jq .

# auto-login brave
curl -s -X POST http://127.0.0.1:8787/api/brave/inject \
  -H 'Content-Type: application/json' -d '{"raw":"<dump>"}' | jq .
```

## Format input

**Netscape** (dump dari browser / ekstensi):
```
domain  include_subdomains  path  secure  expiry  name  value
chatgpt.com	FALSE	/	FALSE	1812869199	oai-hlib	true
.chatgpt.com	TRUE	/	TRUE	1802149501	__Secure-next-auth.session-token.0	...
```

**JSON** (Playwright/ekstensi Cookie-Editor): `{"cookies":[{"name":"...","value":"...","domain":"..."}]}`

## Verdict artinya

| Verdict | Arti |
|---|---|
| `VALID` | Token hidup, backend bisa diakses |
| `REVOKED` | Cookie ada tapi token sudah di-revoke server (`token_revoked`) |
| `INVALID` | `/api/auth/session` gagal (cookie rusak/expired) |
| `PARTIAL` | Session ada tapi tanpa accessToken |
| `DENIED` | Backend menolak (bukan token_revoked) |

## Auto-login Brave

Butuh Brave terinstall (native atau Flatpak). Backend auto-detect lokasi binary.
Cookie di-inject ke **profil isolasi** (`/tmp/brave-rt-profile`) — profil normalmu tidak disentuh.

```bash
curl -X POST http://127.0.0.1:8787/api/brave/launch   # start Brave+CDP
curl -X POST http://127.0.0.1:8787/api/brave/inject -d '{"raw":"<dump>"}' -H 'Content-Type: application/json'
curl -X POST http://127.0.0.1:8787/api/brave/kill     # stop
```

## Lisensi

MIT — lihat [LICENSE](LICENSE).

## Disclaimer

Alat ini untuk menguji sesi/cookie yang **kamu miliki atau punya izin eksplisit** untuk diuji.
Penggunaan terhadap akun milik orang lain tanpa izin melanggar hukum. Penulis tidak bertanggung
jawab atas penyalahgunaan.


## 🎯 Auto-Detect Format Input (v2.1)

Kamu **tidak perlu** memilih format — paste apapun, parser deteksi sendiri:

| Format | Contoh |
|---|---|
| **Netscape** | 7 kolom tab-separated (`domain\tflag\tpath\tsecure\texpiry\tname\tvalue`) |
| **JSON cookies-list** | `{"cookies":[{"name":...,"value":...}]}` atau array `[{...}]` |
| **JSON objek** | `{"name":"value"}` (flat) |
| **Header string** | `a=1; b=2; oai-did=...` |
| **DevTools** | hasil edit cookie / "Copy as cURL" |
| **Bulk / mixed** | banyak blok campur format, dipisah `=== label ===`, baris kosong, atau otomatis |

Parser juga toleran: koma trailing, BOM, `//` komentar, chunking `...token.0/1`,
domain tanpa leading-dot, expiry ISO, dll.



## 🌐 Akses via Tailscale

Server default bind `127.0.0.1`. Untuk akses dari device lain di Tailnet:

### 1. Bind ke semua interface
```bash
HOST=0.0.0.0 PORT=8787 ./run.sh
```

### 2. Akses langsung via IP Tailscale
```bash
tailscale ip -4          # contoh: 100.95.162.3
# buka: http://100.95.162.3:8787
```

### 3. Akses via HTTPS Tailnet (rapi, tanpa buka port)
```bash
tailscale serve --bg --https=8446 http://127.0.0.1:8787
# buka: https://<host>.<tailnet>.ts.net:8446
```

### 4. Autostart permanen (systemd user service)
```ini
# ~/.config/systemd/user/chatgpt-cookie-validator.service
[Unit]
Description=ChatGPT Cookie Validator
After=network-online.target
[Service]
WorkingDirectory=/path/to/app
ExecStart=<venv>/python3 -m uvicorn main:app --host 0.0.0.0 --port 8787
Restart=always
[Install]
WantedBy=default.target
```
```bash
systemctl --user daemon-reload
systemctl --user enable --now chatgpt-cookie-validator.service
systemctl --user status chatgpt-cookie-validator.service
```


## 📦 Bulk Auto-Detector Massal (ZIP / Multi-file)

Upload **1 file ZIP** (isi banyak `.txt`/`.json`/`.csv`/`.log`) atau banyak file sekaligus. Setiap file auto-detect format, auto-split jadi target, verifikasi paralel, output **terstruktur**.

Tab **📦 Bulk ZIP**:
- Drop ZIP atau pilih banyak file
- Atau paste massal (auto-split)
- Ringkasan: total target / alive / revoked / partial
- Tabel per-target: label, verdict, user_email, token_len
- Export: **JSON / CSV / XLSX**

### Endpoint
```
POST /api/bulk/zip?concurrency=6      # multipart file=@cookies.zip
POST /api/bulk/files?concurrency=6    # multipart files=@a.txt -F files=@b.json
POST /api/bulk/paste                  # JSON {"raw": "<paste massal>"}
GET  /api/bulk/export?fmt=csv|xlsx|json
```

### Contoh CLI
```bash
# ZIP -> tabel CSV
curl -s http://127.0.0.1:8787/api/bulk/zip?concurrency=8 -F 'file=@cookies.zip' > out.json
curl -s 'http://127.0.0.1:8787/api/bulk/export?fmt=xlsx' -o hasil.xlsx
```
