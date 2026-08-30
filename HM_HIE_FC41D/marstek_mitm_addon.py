# mitmproxy-Addon: speichert Firmware-Binaries automatisch und loggt OTA-URLs aus MQTT.
# Aufruf:  mitmdump ... -s marstek_mitm_addon.py
from mitmproxy import http
import os, time

OUT = "/mnt/cap/objects"
os.makedirs(OUT, exist_ok=True)

def _log(line):
    with open("/mnt/cap/mitm_hits.log", "a") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line + "\n")

# --- HTTPS-Downloads: Firmware-Dateien automatisch sichern ---
def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    ct  = flow.response.headers.get("content-type", "")
    low = url.lower()
    if low.endswith((".rbl", ".bin")) or "octet-stream" in ct:
        name = (low.split("/")[-1].split("?")[0]) or "download.bin"
        ts   = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(OUT, f"{ts}_{name}")
        with open(path, "wb") as f:
            f.write(flow.response.content)
        _log(f"FIRMWARE  {url}  ->  {path}  ({len(flow.response.content)} Bytes)")

# --- MQTT (raw TLS/TCP): Payloads mit OTA-URL protokollieren ---
def tcp_message(flow):
    m = flow.messages[-1]
    data = bytes(m.content)
    if any(k in data.lower() for k in (b"ota", b"url", b".rbl", b".bin", b"http")):
        try: txt = data.decode("utf-8", "replace")
        except Exception: txt = repr(data)
        _log("MQTT/TCP  " + txt.replace("\n", " ")[:400])
