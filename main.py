#!/usr/bin/env python3
import os, json, time, uuid, secrets, hashlib, threading
import urllib.request, urllib.parse, urllib.error
from datetime import datetime, timedelta
from base64 import b64encode, b64decode
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# ----------------- Config (set via Pella env vars) -----------------
LICENSE_BOT_TOKEN = os.environ.get("LICENSE_BOT_TOKEN", "")
LICENSE_ADMIN_IDS = [int(x) for x in os.environ.get("LICENSE_ADMIN_IDS", "").replace(" ", "").split(",") if x.strip().isdigit()]
LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "change-me-now")
LICENSE_TOKEN_PREFIX = os.environ.get("LICENSE_TOKEN_PREFIX", "LHV")
MAX_DEVICES = int(os.environ.get("LICENSE_MAX_DEVICES", "1") or 1)
PORT = int(os.environ.get("PORT", os.environ.get("LICENSE_API_PORT", "8787") or 8787))
HOST = os.environ.get("LICENSE_API_HOST", "0.0.0.0")

DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(DATA_DIR, exist_ok=True)
LICENSE_DB_FILE = os.path.join(DATA_DIR, "license_store.enc")

# ----------------- Crypto helpers -----------------
def _derive_crypto_key(seed: str) -> bytes:
    return hashlib.sha256((LICENSE_SECRET + seed).encode("utf-8")).digest()

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def _encrypt_payload(payload: dict, seed: str) -> str:
    blob = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    key = _derive_crypto_key(seed)
    return b64encode(_xor_bytes(blob, key)).decode("utf-8")

def _decrypt_payload(token: str, seed: str):
    try:
        raw = b64decode(token.encode("utf-8"))
        key = _derive_crypto_key(seed)
        decoded = _xor_bytes(raw, key)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return None

# ----------------- License store -----------------
class LicenseStore:
    def __init__(self, path=LICENSE_DB_FILE, max_devices=1):
        self.path = path
        self.max_devices = max(1, int(max_devices))
        self.lock = threading.Lock()
        self.data = {"licenses": {}}
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            raw = open(self.path, "r", encoding="utf-8").read().strip()
            payload = _decrypt_payload(raw, seed="server")
            if isinstance(payload, dict) and "licenses" in payload:
                self.data = payload
        except Exception:
            self.data = {"licenses": {}}

    def _persist(self):
        token = _encrypt_payload(self.data, seed="server")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(token)

    def _normalize_plan(self, plan):
        return (plan or "").lower()

    def _duration_for_plan(self, plan, custom_days=None):
        plan = self._normalize_plan(plan)
        aliases = {"one": "1d", "1day": "1d", "1week": "1w", "1month": "1m", "12m": "1y", "12mo": "1y", "lifetime": "life"}
        plan = aliases.get(plan, plan)
        days_lookup = {
            "1d": 1, "1w": 7, "1m": 30, "3m": 90, "6m": 180,
            "1y": 365, "life": 36500, "custom": max(1, int(custom_days or 1))
        }
        return timedelta(days=days_lookup.get(plan, 30))

    def _generate_key(self):
        return f"{LICENSE_TOKEN_PREFIX}-{secrets.token_hex(4).upper()}-{secrets.token_hex(3).upper()}"

    def _refresh_status(self, entry):
        expiry = entry.get("expiry")
        status = entry.get("status", "active")
        if expiry:
            try:
                if datetime.utcnow() > datetime.fromisoformat(expiry) and status != "disabled":
                    entry["status"] = "expired"
            except Exception:
                entry["status"] = "expired"
        return entry

    def create_license(self, plan, custom_days=None, note=""):
        with self.lock:
            key = self._generate_key()
            now = datetime.utcnow()
            expiry = now + self._duration_for_plan(plan, custom_days)
            entry = {
                "key": key, "plan": self._normalize_plan(plan), "start": now.isoformat(),
                "expiry": expiry.isoformat(), "status": "active", "devices": [], "note": note or ""
            }
            self.data["licenses"][key] = entry
            self._persist()
            return entry

    def renew_license(self, key, plan, custom_days=None):
        with self.lock:
            entry = self.data["licenses"].get(key)
            if not entry:
                return None, "License not found"
            now = datetime.utcnow()
            expiry = now + self._duration_for_plan(plan, custom_days)
            entry.update({"plan": self._normalize_plan(plan), "start": now.isoformat(), "expiry": expiry.isoformat(), "status": "active"})
            self.data["licenses"][key] = entry
            self._persist()
            return entry, "renewed"

    def disable_license(self, key):
        with self.lock:
            entry = self.data["licenses"].get(key)
            if not entry:
                return None, "License not found"
            entry["status"] = "disabled"
            self.data["licenses"][key] = entry
            self._persist()
            return entry, "disabled"

    def list_keys(self, status=None):
        with self.lock:
            out = []
            for lic in self.data["licenses"].values():
                lic = self._refresh_status(dict(lic))
                if status and lic.get("status") != status:
                    continue
                out.append(lic)
            return out

    def get_info(self, key):
        with self.lock:
            entry = self.data["licenses"].get(key)
            if not entry:
                return None
            entry = self._refresh_status(dict(entry))
            self.data["licenses"][key] = entry
            self._persist()
            return entry

    def validate_license(self, key, device_id):
        with self.lock:
            entry = self.data["licenses"].get(key)
            if not entry:
                return False, None, "License not found"
            entry = self._refresh_status(entry)
            if entry.get("status") == "disabled":
                return False, entry, "License disabled"
            if entry.get("status") == "expired":
                return False, entry, "License expired"
            devices = entry.get("devices") or []
            if device_id not in devices:
                if len(devices) >= self.max_devices:
                    return False, entry, "License already bound to another device"
                devices.append(device_id)
            entry["devices"] = devices
            entry["device_id"] = devices[0] if devices else ""
            entry["last_check"] = datetime.utcnow().isoformat()
            self.data["licenses"][key] = entry
            self._persist()
            return True, entry, "ok"

# ----------------- Telegram admin bot (polling) -----------------
class TelegramAdminBot:
    def __init__(self, store: LicenseStore, token: str, admin_ids):
        self.store = store
        self.token = token
        self.admin_ids = set(admin_ids or [])
        self.base = f"https://api.telegram.org/bot{token}" if token else ""
        self.running = False
        self.thread = None
        self.offset = 0

    def start(self):
        if self.running or not self.token or not self.admin_ids:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _tg_get(self, method, params=None, timeout=30):
        try:
            url = f"{self.base}/{method}"
            if params:
                url += "?" + urllib.parse.urlencode(params)
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data
        except Exception:
            return None

    def _tg_post(self, method, params=None, timeout=30):
        try:
            url = f"{self.base}/{method}"
            data = urllib.parse.urlencode(params or {}).encode("utf-8")
            with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data
        except Exception:
            return None

    def _send(self, chat_id, text):
        self._tg_post("sendMessage", {"chat_id": chat_id, "text": text})

    def _loop(self):
        while self.running:
            upd = self._tg_get("getUpdates", {"timeout": 20, "offset": self.offset + 1}, timeout=25)
            if not upd or not upd.get("ok"):
                time.sleep(2)
                continue
            for u in upd.get("result", []):
                self.offset = max(self.offset, u.get("update_id", 0))
                msg = u.get("message") or u.get("edited_message")
                if msg:
                    self._handle(msg)

    def _handle(self, message):
        chat_id = message.get("chat", {}).get("id")
        user_id = message.get("from", {}).get("id")
        text = (message.get("text") or "").strip()
        if not chat_id or not user_id or not text:
            return
        if user_id not in self.admin_ids:
            self._send(chat_id, "Unauthorized.")
            return
        parts = text.split()
        cmd = parts[0].split("@")[0].lower()
        args = parts[1:]
        if cmd == "/newkey":
            if not args:
                self._send(chat_id, "Usage: /newkey <plan> [days] [note]")
                return
            plan = args[0]; custom_days = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
            note = " ".join(args[2:]) if len(args) > 2 else ""
            entry = self.store.create_license(plan, custom_days=custom_days, note=note)
            self._send(chat_id, f"Created: {entry['key']} | plan={entry['plan']} | exp={entry['expiry']}")
        elif cmd == "/renewkey":
            if len(args) < 2:
                self._send(chat_id, "Usage: /renewkey <key> <plan> [days]")
                return
            key, plan = args[0], args[1]; custom_days = int(args[2]) if len(args) > 2 and args[2].isdigit() else None
            entry, msg = self.store.renew_license(key, plan, custom_days)
            self._send(chat_id, msg if not entry else f"Renewed {key} -> {entry['plan']} exp {entry['expiry']}")
        elif cmd == "/disablekey":
            if not args:
                self._send(chat_id, "Usage: /disablekey <key>")
                return
            entry, msg = self.store.disable_license(args[0])
            self._send(chat_id, msg if not entry else f"Disabled {args[0]}")
        elif cmd == "/keyinfo":
            if not args:
                self._send(chat_id, "Usage: /keyinfo <key>")
                return
            entry = self.store.get_info(args[0])
            if not entry:
                self._send(chat_id, "Not found")
                return
            devices = ", ".join(entry.get("devices") or []) or "Unbound"
            self._send(chat_id, f"Key: {entry['key']}\nPlan: {entry['plan']}\nStatus: {entry['status']}\nStart: {entry.get('start')}\nExpiry: {entry.get('expiry')}\nDevices: {devices}\nNote: {entry.get('note','')}")
        elif cmd == "/listkeys":
            status = args[0] if args else None
            items = self.store.list_keys(status=status)
            if not items:
                self._send(chat_id, "No keys.")
                return
            lines = [f"{i['key']} | {i['plan']} | {i['status']} | exp {i.get('expiry')}" for i in items[:30]]
            self._send(chat_id, "\n".join(lines))
        elif cmd == "/maintenance":
            self._send(chat_id, "Maintenance toggle not implemented in this minimal bot.")
        else:
            self._send(chat_id, "Commands: /newkey /renewkey /disablekey /keyinfo /listkeys")

# ----------------- HTTP API -----------------
class LicenseAPIServer:
    def __init__(self, store: LicenseStore, host=HOST, port=PORT):
        self.store = store
        self.host = host
        self.port = port
        self.server = None

    def start(self):
        store = self.store
        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path.startswith("/health"):
                    self._send(200, {"status": "ok"})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                if self.path.startswith("/api/license/validate"):
                    try:
                        length = int(self.headers.get("Content-Length") or 0)
                        payload = json.loads(self.rfile.read(length or 0).decode("utf-8"))
                    except Exception:
                        self._send(400, {"ok": False, "error": "Invalid JSON"})
                        return
                    key = (payload.get("key") or "").strip()
                    device_id = (payload.get("device_id") or "").strip()
                    if not key or not device_id:
                        self._send(400, {"ok": False, "error": "Missing key/device"})
                        return
                    ok, info, msg = store.validate_license(key, device_id)
                    if ok:
                        self._send(200, {"ok": True, "plan": info.get("plan"), "status": info.get("status"), "start": info.get("start"), "expiry": info.get("expiry"), "device_id": info.get("device_id"), "note": info.get("note","")})
                    else:
                        self._send(403, {"ok": False, "error": msg, "status": info.get("status") if info else ""})
                else:
                    self._send(404, {"error": "not found"})
            def log_message(self, *args, **kwargs):
                return
        self.server = ThreadingHTTPServer((self.host, self.port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        print(f"License API running on {self.host}:{self.port}")

# ----------------- Main -----------------
if __name__ == "__main__":
    store = LicenseStore(max_devices=MAX_DEVICES)
    bot = TelegramAdminBot(store, LICENSE_BOT_TOKEN, LICENSE_ADMIN_IDS)
    bot.start()
    api = LicenseAPIServer(store, host=HOST, port=PORT)
    api.start()
    print("License service started. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
