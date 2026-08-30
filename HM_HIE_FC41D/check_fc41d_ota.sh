#!/usr/bin/env bash
# Überwacht die Comm-Modul-Firmware (FC41D) des Marstek Venus D.
# Der Dateiname ist statisch -> Versionserkennung nur über Header + Hash.
#
#   chmod +x check_fc41d_ota.sh
#   ./check_fc41d_ota.sh          einmal prüfen
#   ./check_fc41d_ota.sh --fetch  bei Änderung Datei herunterladen und archivieren
set -uo pipefail

URL="http://www.hamedata.com/app/download/neng/HM_HIE_FC41D_remote_ota.rbl"
STATE="${STATE_FILE:-$HOME/.fc41d_ota_state}"
ARCHIVE="${ARCHIVE_DIR:-./fc41d_archive}"

hdr=$(curl -sSI --max-time 20 "$URL") || { echo "FEHLER: Request fehlgeschlagen"; exit 1; }
code=$(printf '%s' "$hdr" | awk 'NR==1{print $2}')
[ "$code" = "200" ] || { echo "HTTP $code – Datei nicht abrufbar"; printf '%s\n' "$hdr"; exit 1; }

get() { printf '%s' "$hdr" | tr -d '\r' | grep -i "^$1:" | cut -d' ' -f2- | tail -1; }
lastmod=$(get 'last-modified'); size=$(get 'content-length'); etag=$(get 'etag')

echo "URL           : $URL"
echo "Last-Modified : ${lastmod:-<fehlt>}"
echo "Content-Length: ${size:-<fehlt>} Bytes"
echo "ETag          : ${etag:-<fehlt>}"

sig="${lastmod}|${size}|${etag}"
if [ -f "$STATE" ]; then
  prev=$(cat "$STATE")
  if [ "$sig" = "$prev" ]; then
    echo "Status        : unverändert"
  else
    echo "Status        : *** GEÄNDERT ***"
    echo "  vorher: $prev"
    echo "  jetzt : $sig"
  fi
else
  echo "Status        : erste Messung (Referenz wird angelegt)"
fi
printf '%s' "$sig" > "$STATE"

if [ "${1:-}" = "--fetch" ]; then
  mkdir -p "$ARCHIVE"
  tmp=$(mktemp)
  curl -sS --max-time 120 -o "$tmp" "$URL" || { echo "Download fehlgeschlagen"; rm -f "$tmp"; exit 1; }
  sha=$(shasum -a 256 "$tmp" | cut -d' ' -f1)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  out="$ARCHIVE/HM_HIE_FC41D_remote_ota_${stamp}_${sha:0:12}.rbl"
  if ls "$ARCHIVE"/*_"${sha:0:12}".rbl >/dev/null 2>&1; then
    echo "SHA256        : $sha (bereits archiviert)"
    rm -f "$tmp"
  else
    mv "$tmp" "$out"
    echo "SHA256        : $sha"
    echo "archiviert    : $out"
  fi
fi