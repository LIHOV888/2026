#!/usr/bin/env python3
import os, json, time, uuid, secrets, hashlib, threading
import urllib.request, urllib.parse, urllib.error
from datetime import datetime, timedelta
from base64 import b64encode, b64decode
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from io import BytesIO

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

AUDIT_LOGS = []
INTERACTIVE_LICENSE_BOT = None

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

    def update_note(self, key, note):
        with self.lock:
            entry = self.data["licenses"].get(key)
            if not entry:
                return None, "License not found"
            entry["note"] = note or ""
            self.data["licenses"][key] = entry
            self._persist()
            return entry, "updated"

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
class InteractiveLicenseBot:
    def __init__(self, store: LicenseStore, bot_token, admin_ids):
        self.store = store
        self.bot_token = bot_token
        self.admin_ids = set(admin_ids or [])
        self.base_url = f"https://api.telegram.org/bot{bot_token}" if bot_token else ""
        self.running = False
        self.thread = None
        self.offset = 0
        self.user_states = {}
        self.maintenance_mode = False

    def _tg_call(self, method, params=None, files=None):
        url = f"{self.base_url}/{method}"
        data = None
        headers = {}

        if files:
            boundary = f"-----WebKitFormBoundary{uuid.uuid4().hex}"
            body = BytesIO()

            def add_field(name, value):
                body.write(f"--{boundary}\r\n".encode("utf-8"))
                body.write(f'Content-Disposition: form-data; name=\"{name}\"\r\n\r\n'.encode("utf-8"))
                body.write(str(value).encode("utf-8"))
                body.write(b"\r\n")

            if params:
                for name, value in params.items():
                    add_field(name, value)

            for fname, fcontent, mime in files:
                body.write(f"--{boundary}\r\n".encode("utf-8"))
                body.write(f'Content-Disposition: form-data; name=\"document\"; filename=\"{fname}\"\r\n'.encode("utf-8"))
                body.write(f"Content-Type: {mime}\r\n\r\n".encode("utf-8"))
                body.write(fcontent)
                body.write(b"\r\n")

            body.write(f"--{boundary}--\r\n".encode("utf-8"))
            data = body.getvalue()
            headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        elif params:
            data = json.dumps(params).encode('utf-8')
            headers = {'Content-Type': 'application/json'}

        try:
            req = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                return bool(res_data.get("ok")), res_data.get("result")
        except Exception as e:
            print(f"TG Error ({method}): {e}")
            return False, None

    def _send_message(self, chat_id, text, reply_markup=None):
        params = {"chat_id": chat_id, "text": text}
        if reply_markup:
            params["reply_markup"] = reply_markup
        self._tg_call("sendMessage", params=params)

    # --- Menus ---
    def _home_menu(self):
        return {"inline_keyboard": [
            [{"text": "🔑 Create License", "callback_data": "create"}, {"text": "📂 Manage Licenses", "callback_data": "manage"}],
            [{"text": "⚙️ Admin Tools", "callback_data": "admin"}, {"text": "📊 Analytics", "callback_data": "analytics"}]
        ]}

    def _manage_menu(self):
        return {"inline_keyboard": [
            [{"text": "🔍 Search by Key", "callback_data": "search_key"}, {"text": "👤 Search by UserID/HWID", "callback_data": "search_user"}],
            [{"text": "📂 View Active", "callback_data": "view_active:0"}, {"text": "📂 View Expired", "callback_data": "view_expired:0"}],
            [{"text": "📂 View Disabled", "callback_data": "view_disabled:0"}, {"text": "🔙 Home", "callback_data": "home"}]
        ]}

    def _admin_menu(self):
        return {"inline_keyboard": [
            [{"text": "📢 Broadcast", "callback_data": "broadcast"}, {"text": "🧹 Bulk Delete Expired", "callback_data": "bulk_delete"}],
            [{"text": "📜 View Audit Logs", "callback_data": "view_logs"}, {"text": "🏗️ Maintenance Mode", "callback_data": "maintenance"}],
            [{"text": "⬇️ Export Database", "callback_data": "export_db"}, {"text": "🔙 Home", "callback_data": "home"}]
        ]}

    def _analytics_menu(self):
        return {"inline_keyboard": [[{"text": "📈 Live Stats", "callback_data": "live_stats"}], [{"text": "🔙 Home", "callback_data": "home"}]]}

    def _plan_menu(self):
        return {"inline_keyboard": [
            [{"text": "1 Day", "callback_data": "plan:1d"}, {"text": "1 Week", "callback_data": "plan:1w"}],
            [{"text": "1 Month", "callback_data": "plan:1m"}, {"text": "Lifetime", "callback_data": "plan:life"}],
            [{"text": "✏️ Custom Days", "callback_data": "plan:custom"}, {"text": "🔙 Back", "callback_data": "home"}]
        ]}
    
    def _quantity_menu(self, plan):
        return {"inline_keyboard": [
            [{"text": "1 Key", "callback_data": f"qty:{plan}:1"}, {"text": "5 Keys", "callback_data": f"qty:{plan}:5"}, {"text": "10 Keys", "callback_data": f"qty:{plan}:10"}],
            [{"text": "🔙 Back", "callback_data": "create"}]
        ]}

    def _detail_menu(self, entry):
        key = entry.get("key")
        status = entry.get("status")
        toggle_text = "❄️ Freeze" if status != "disabled" else "🔓 Enable"
        return {"inline_keyboard": [
            [{"text": "⏳ Extend Time", "callback_data": f"extend:{key}"}, {"text": toggle_text, "callback_data": f"toggle:{key}"}],
            [{"text": "🔓 Reset HWID", "callback_data": f"reset:{key}"}, {"text": "✏️ Edit Note", "callback_data": f"note:{key}"}],
            [{"text": "🗑️ Delete", "callback_data": f"delete:{key}"}, {"text": "🔙 Back", "callback_data": "manage"}]
        ]}

    def _extend_menu(self, key):
        return {"inline_keyboard": [
            [{"text": "+1 Day", "callback_data": f"extend_do:{key}:1d"}, {"text": "+1 Month", "callback_data": f"extend_do:{key}:1m"}, {"text": "+1 Year", "callback_data": f"extend_do:{key}:1y"}],
            [{"text": "🔙 Back", "callback_data": f"detail:{key}"}]
        ]}

    def start(self):
        if self.running or not self.bot_token: return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        print("Telegram Bot Started")

    def _loop(self):
        while self.running:
            try:
                params = {"offset": self.offset + 1, "timeout": 30, "allowed_updates": ["message", "callback_query"]}
                ok, result = self._tg_call("getUpdates", params=params)
                if ok and result:
                    for update in result:
                        self.offset = max(self.offset, update.get("update_id", 0))
                        if "callback_query" in update:
                            self._handle_callback(update["callback_query"])
                        elif "message" in update:
                            self._handle_message(update["message"])
            except Exception:
                time.sleep(5)

    def _handle_message(self, message):
        chat_id = message.get("chat", {}).get("id")
        user_id = message.get("from", {}).get("id")
        text = message.get("text", "").strip()
        
        if user_id not in self.admin_ids:
            return

        state = self.user_states.get(chat_id, {})
        mode = state.get("state")
        
        if text == "/start" or text == "/home":
            self.user_states[chat_id] = {}
            self._send_message(chat_id, "🏠 Main Dashboard", reply_markup=self._home_menu())
            return

        if mode == "await_custom_days":
            if text.isdigit():
                days = int(text)
                self.user_states[chat_id] = {"state": "plan_selected", "plan": "custom", "custom_days": days}
                self._send_message(chat_id, f"Custom Plan: {days} Days selected.\nSelect Quantity:", reply_markup=self._quantity_menu("custom"))
            else:
                self._send_message(chat_id, "Please enter a valid number of days.")
            return

        if mode == "search_key":
            lic = self.store.get_info(text)
            if not lic:
                self._send_message(chat_id, "License not found.", reply_markup=self._manage_menu())
            else:
                self._send_license_detail(chat_id, lic)
            self.user_states[chat_id] = {}
            return

        if mode == "search_user":
            results = []
            for lic in self.store.list_keys():
                devices = lic.get("devices") or []
                legacy_id = lic.get("device_id")
                if text in devices or (legacy_id and legacy_id == text):
                    results.append(lic["key"])
            if not results:
                self._send_message(chat_id, "No licenses found for this user.", reply_markup=self._manage_menu())
            else:
                self.user_states[chat_id] = {"state": "search_results", "results": results, "page": 0}
                self._send_search_list(chat_id)
            return

        if mode == "edit_note":
            key = state.get("key")
            lic = self.store.get_info(key)
            if lic:
                lic["note"] = text
                with self.store.lock:
                    self.store.data["licenses"][key] = lic
                    self.store._persist()
                AUDIT_LOGS.append((datetime.utcnow().isoformat(), f"Edited note for {key}"))
                self._send_license_detail(chat_id, lic, msg="Note updated.")
            self.user_states[chat_id] = {}
            return

        if mode == "broadcast":
            AUDIT_LOGS.append((datetime.utcnow().isoformat(), f"Broadcast: {text}"))
            self._send_message(chat_id, f"Broadcast Sent:\n\n{text}", reply_markup=self._admin_menu())
            self.user_states[chat_id] = {}
            return

        # Fallback
        self._send_message(chat_id, "Use the menu buttons.", reply_markup=self._home_menu())

    def _handle_callback(self, cb):
        chat_id = cb.get("message", {}).get("chat", {}).get("id")
        user_id = cb.get("from", {}).get("id")
        data = cb.get("data")
        
        if user_id not in self.admin_ids: return
        self._tg_call("answerCallbackQuery", params={"callback_query_id": cb["id"]})

        if data == "noop": return
        
        # --- HOME ---
        if data == "home":
            self.user_states[chat_id] = {}
            self._send_message(chat_id, "🏠 Main Dashboard", reply_markup=self._home_menu())
        
        # --- CREATE ---
        elif data == "create":
            self.user_states[chat_id] = {"state": "create"}
            self._send_message(chat_id, "Select Plan:", reply_markup=self._plan_menu())
            
        elif data.startswith("plan:"):
            plan = data.split(":")[1]
            if plan == "custom":
                self.user_states[chat_id] = {"state": "await_custom_days"}
                self._send_message(chat_id, "Enter duration in days (e.g. 7):")
            else:
                self.user_states[chat_id] = {"state": "plan_selected", "plan": plan}
                self._send_message(chat_id, f"Plan: {plan}\nSelect Quantity:", reply_markup=self._quantity_menu(plan))

        elif data.startswith("qty:"):
            parts = data.split(":")
            plan = parts[1]
            qty = int(parts[2])
            
            # Retrieve custom days from state if present
            state = self.user_states.get(chat_id, {})
            custom_days = state.get("custom_days")
            
            keys = []
            for _ in range(qty):
                entry = self.store.create_license(plan, custom_days=custom_days)
                keys.append(entry["key"])
                AUDIT_LOGS.append((datetime.utcnow().isoformat(), f"Created {entry['key']} ({plan})"))
            
            if qty == 1:
                self._send_message(chat_id, f"License Created:\n`{keys[0]}`", reply_markup=self._home_menu())
            else:
                content = "\n".join(keys)
                self._tg_call("sendDocument", params={"chat_id": chat_id, "caption": f"{qty} Keys Created"}, files=[("keys.txt", content.encode("utf-8"), "text/plain")])
                self._send_message(chat_id, "Keys generated.", reply_markup=self._home_menu())
            self.user_states[chat_id] = {}

        # --- MANAGE ---
        elif data == "manage":
            self.user_states[chat_id] = {}
            self._send_message(chat_id, "Manage Licenses", reply_markup=self._manage_menu())

        elif data == "search_key":
            self.user_states[chat_id] = {"state": "search_key"}
            self._send_message(chat_id, "Enter License Key:")

        elif data == "search_user":
            self.user_states[chat_id] = {"state": "search_user"}
            self._send_message(chat_id, "Enter UserID/HWID:")

        elif data.startswith("view_"):
            parts = data.split(":")
            status = parts[0][5:]
            page = int(parts[1]) if len(parts) > 1 else 0
            self.user_states[chat_id] = {"state": "list", "status": status, "page": page}
            self._send_list(chat_id)

        elif data.startswith("prev:") or data.startswith("next:"):
            parts = data.split(":")
            direction = parts[0]
            status = parts[1]
            page = int(parts[2])
            page = page - 1 if direction == "prev" else page + 1
            self.user_states[chat_id] = {"state": "list", "status": status, "page": page}
            self._send_list(chat_id)

        # --- DETAILS / ACTIONS ---
        elif data.startswith("detail:"):
            key = data.split(":", 1)[1]
            lic = self.store.get_info(key)
            if lic: self._send_license_detail(chat_id, lic)
            else: self._send_message(chat_id, "Not found.")

        elif data.startswith("extend:"):
            key = data.split(":", 1)[1]
            self._send_message(chat_id, "Select Extension:", reply_markup=self._extend_menu(key))

        elif data.startswith("extend_do:"):
            parts = data.split(":")
            key, period = parts[1], parts[2]
            lic = self.store.get_info(key)
            if lic:
                delta = self.store._duration_for_plan(period)
                try: exp = datetime.fromisoformat(lic["expiry"])
                except: exp = datetime.utcnow()
                lic["expiry"] = (exp + delta).isoformat()
                lic["status"] = "active"
                with self.store.lock:
                    self.store.data["licenses"][key] = lic
                    self.store._persist()
                AUDIT_LOGS.append((datetime.utcnow().isoformat(), f"Extended {key} by {period}"))
                self._send_license_detail(chat_id, lic, "Extended Successfully.")

        elif data.startswith("toggle:"):
            key = data.split(":", 1)[1]
            lic = self.store.get_info(key)
            if lic:
                new_status = "disabled" if lic.get("status") != "disabled" else "active"
                lic["status"] = new_status
                with self.store.lock:
                    self.store.data["licenses"][key] = lic
                    self.store._persist()
                AUDIT_LOGS.append((datetime.utcnow().isoformat(), f"Toggled {key} to {new_status}"))
                self._send_license_detail(chat_id, lic, f"Status changed to {new_status}")

        elif data.startswith("reset:"):
            key = data.split(":", 1)[1]
            lic = self.store.get_info(key)
            if lic:
                lic["devices"] = []
                lic.pop("device_id", None)
                with self.store.lock:
                    self.store.data["licenses"][key] = lic
                    self.store._persist()
                AUDIT_LOGS.append((datetime.utcnow().isoformat(), f"Reset HWID for {key}"))
                self._send_license_detail(chat_id, lic, "HWID Reset.")

        elif data.startswith("note:"):
            key = data.split(":", 1)[1]
            self.user_states[chat_id] = {"state": "edit_note", "key": key}
            self._send_message(chat_id, "Send new note text:")

        elif data.startswith("delete:"):
            key = data.split(":", 1)[1]
            with self.store.lock:
                self.store.data["licenses"].pop(key, None)
                self.store._persist()
            AUDIT_LOGS.append((datetime.utcnow().isoformat(), f"Deleted {key}"))
            self._send_message(chat_id, f"Deleted {key}.", reply_markup=self._manage_menu())

        # --- ADMIN ---
        elif data == "admin":
            self.user_states[chat_id] = {}
            self._send_message(chat_id, "Admin Tools", reply_markup=self._admin_menu())

        elif data == "broadcast":
            self.user_states[chat_id] = {"state": "broadcast"}
            self._send_message(chat_id, "Send message to broadcast:")

        elif data == "maintenance":
            self.maintenance_mode = not self.maintenance_mode
            status = "ON" if self.maintenance_mode else "OFF"
            AUDIT_LOGS.append((datetime.utcnow().isoformat(), f"Maintenance: {status}"))
            self._send_message(chat_id, f"Maintenance Mode: {status}", reply_markup=self._admin_menu())

        elif data == "export_db":
            if os.path.exists(LICENSE_DB_FILE):
                with open(LICENSE_DB_FILE, "rb") as f: content = f.read()
                self._tg_call("sendDocument", params={"chat_id": chat_id}, files=[("license_store.enc", content, "application/octet-stream")])
            else:
                self._send_message(chat_id, "DB is empty.")

        elif data == "bulk_delete":
             count = 0
             now = datetime.utcnow()
             with self.store.lock:
                 keys_to_del = []
                 for k, v in list(self.store.data["licenses"].items()):
                     try:
                        exp = datetime.fromisoformat(v["expiry"])
                        if (now - exp).days > 30: keys_to_del.append(k)
                     except: pass
                 for k in keys_to_del:
                     del self.store.data["licenses"][k]
                     count += 1
                 if count: self.store._persist()
             AUDIT_LOGS.append((datetime.utcnow().isoformat(), f"Bulk deleted {count} keys"))
             self._send_message(chat_id, f"Deleted {count} old expired keys.", reply_markup=self._admin_menu())

        elif data == "view_logs":
             logs = "\n".join([f"{ts}: {msg}" for ts, msg in AUDIT_LOGS[-15:]]) or "No logs."
             self._send_message(chat_id, f"Audit Logs:\n{logs}", reply_markup=self._admin_menu())

        # --- ANALYTICS ---
        elif data == "analytics":
             self._send_message(chat_id, "Analytics", reply_markup=self._analytics_menu())

        elif data == "live_stats":
            total = len(self.store.list_keys())
            active = len(self.store.list_keys("active"))
            expired = len(self.store.list_keys("expired"))
            msg = f"📊 Live Stats:\n\nTotal Keys: {total}\nActive: {active}\nExpired: {expired}"
            self._send_message(chat_id, msg, reply_markup=self._analytics_menu())

    # --- Helpers ---
    def _send_list(self, chat_id):
        state = self.user_states.get(chat_id, {})
        status = state.get("status")
        page = state.get("page", 0)
        page_size = 10
        
        if status == "search": keys = state.get("results", [])
        else: keys = [l["key"] for l in self.store.list_keys(status)]
        
        total_pages = max(1, (len(keys) + page_size - 1) // page_size)
        page = max(0, min(page, total_pages - 1))
        
        subset = keys[page*page_size : (page+1)*page_size]
        keyboard = [[{"text": k, "callback_data": f"detail:{k}"}] for k in subset]
        
        nav = []
        if page > 0: nav.append({"text": "⬅️ Prev", "callback_data": f"prev:{status}:{page}"})
        nav.append({"text": f"{page+1}/{total_pages}", "callback_data": "noop"})
        if page < total_pages - 1: nav.append({"text": "Next ➡️", "callback_data": f"next:{status}:{page}"})
        if nav: keyboard.append(nav)
        
        keyboard.append([{"text": "🔙 Back", "callback_data": "manage"}])
        
        self._send_message(chat_id, f"List ({status}):", reply_markup={"inline_keyboard": keyboard})

    def _send_search_list(self, chat_id):
        state = self.user_states.get(chat_id, {})
        state["status"] = "search"
        self._send_list(chat_id)

    def _send_license_detail(self, chat_id, lic, msg=""):
        key = lic["key"]
        text = f"{msg}\n\nKey: `{key}`\nPlan: {lic.get('plan')}\nStatus: {lic.get('status')}\nExpires: {lic.get('expiry')}\nHWID: {lic.get('device_id') or 'Unbound'}\nNote: {lic.get('note','')}"
        self._send_message(chat_id, text, reply_markup=self._detail_menu(lic))

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
                    if INTERACTIVE_LICENSE_BOT and getattr(INTERACTIVE_LICENSE_BOT, "maintenance_mode", False):
                        self._send(503, {"ok": False, "error": "Maintenance Mode"})
                        return
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
    print("License service starting...")
    store = LicenseStore(max_devices=MAX_DEVICES)

    if LICENSE_BOT_TOKEN:
        bot = InteractiveLicenseBot(store, LICENSE_BOT_TOKEN, LICENSE_ADMIN_IDS)
        INTERACTIVE_LICENSE_BOT = bot
        bot.start()
    else:
        print("WARNING: LICENSE_BOT_TOKEN not set. Telegram bot will not start.")

    api = LicenseAPIServer(store, host=HOST, port=PORT)
    api.start()
    print(f"License service started on {HOST}:{PORT}. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
