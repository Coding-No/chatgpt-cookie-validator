#!/usr/bin/env bash
# ============================================================
# device_browser.sh — Jalankan browser DI DEVICE KAMU dengan
# remote debugging aktif, biar server bisa nyetir browser ini.
# ============================================================
# Pemakaian:
#   ./device_browser.sh                    # auto-detect browser
#   ./device_browser.sh chrome             # paksa chrome
#   ./device_browser.sh brave 9333         # paksa brave + port 9333
#   ./device_browser.sh --list             # lihat browser yg terdeteksi
# ============================================================
set -euo pipefail

PORT="${2:-9222}"
WHICH="${1:-auto}"
PROFILE="${DEVICE_PROFILE:-$HOME/.cgpt_device_profile}"

detect() {
  local cands=()
  case "$(uname -s)" in
    Darwin)
      cands+=("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser")
      cands+=("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
      cands+=("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")
      cands+=("/Applications/Chromium.app/Contents/MacOS/Chromium")
      ;;
    Linux)
      cands+=("brave-browser" "brave" "google-chrome" "google-chrome-stable" "chromium" "chromium-browser" "microsoft-edge")
      ;;
    MINGW*|MSYS*|CYGWIN*)
      cands+=("/c/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe")
      cands+=("/c/Program Files/Google/Chrome/Application/chrome.exe")
      cands+=("/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")
      ;;
  esac
  for c in "${cands[@]}"; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then echo "$c"; return 0; fi
  done
  return 1
}

pick() {
  case "$WHICH" in
    --list|list) echo "Kandidat di sistem ini:"; detect || echo "  (tidak ada yg terdeteksi otomatis)"; exit 0;;
    auto) detect || { echo "❌ Browser tidak ditemukan otomatis. Jalankan: $0 <path-ke-browser> $PORT"; exit 1; };;
    chrome|google-chrome) command -v google-chrome google-chrome-stable chrome >/dev/null 2>&1 && { command -v google-chrome || command -v google-chrome-stable || command -v chrome; } || { echo "❌ chrome tidak ada di PATH"; exit 1; };;
    brave) command -v brave-browser || command -v brave || { echo "❌ brave tidak ada di PATH"; exit 1; };;
    *) echo "$WHICH";;
  esac
}

BIN="$(pick)"

echo "================================================"
echo " 🧑‍💻 Browser device-mode"
echo " Binary : $BIN"
echo " Port CDP: $PORT"
echo " Profile: $PROFILE  (cookie akun tersimpan di sini)"
echo "================================================"
mkdir -p "$PROFILE"

# IP tailnet device ini (biar gampang dicatat di server)
if command -v tailscale >/dev/null 2>&1; then
  echo " 🌐 IP tailnet device: $(tailscale ip -4 2>/dev/null || echo '?')"
fi
echo ""
echo "➡️  Setelah jendela terbuka, balik ke tool (tab 🧑‍💻 Banyak Akun),"
echo "    isi host = IP di atas, port = $PORT, klik 'Cek device'."
echo "    Tutup jendela ini = browser mati."
echo ""

# JANGAN jalankan bersamaan dgn browser biasa (bentrok profile) -> pakai profile terpisah
"$BIN" \
  --remote-debugging-port="$PORT" \
  --remote-allow-origins='*' \
  --user-data-dir="$PROFILE" \
  --no-first-run \
  --no-default-browser-check \
  --disable-features=ChromeWhatsNewUI \
  "https://chatgpt.com/" >/dev/null 2>&1
