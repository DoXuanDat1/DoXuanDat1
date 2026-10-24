import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, request

try:
    from websockets.sync.client import connect as ws_connect

    WS_OK = True
except Exception:
    WS_OK = False

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

APP_PORT = 8787
APP_VERSION = "1.3-keys"
IS_BACKGROUND = "--background" in sys.argv
UA = {"User-Agent": "TerminalKeeper/1.0"}

KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keeper_keys.json")
PROXY_PORTS = tuple(range(2000, 2200))
DEFAULT_OPTIONS = {
    "interval": 60,
    "keepalive_sec": 1800,
    "auto_resume": True,
    "ws_attach": True,
    "activity_ping": False,
    "proxy": True,
    "auto_start": True,
}
STORE = {"version": 1, "keys": [], "options": dict(DEFAULT_OPTIONS)}
KEYLOCK = threading.Lock()
KEYINFO = {}
EVENTS = deque(maxlen=120)
PROXY_LOCK = threading.Lock()
PROXY_STATS = {"via": 0, "fallback": 0}
_proxy_ix = 0


def find_keeper_pids():
    try:
        out = subprocess.check_output(
            [
                "wmic", "process",
                "where", "name like 'python%'",
                "get", "ProcessId,CommandLine", "/format:csv",
            ],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", "replace")
        pids = []
        for line in out.splitlines():
            if "terminal_keeper.py" in line.lower():
                parts = line.strip().rsplit(",", 1)
                if parts[-1].isdigit():
                    pids.append(int(parts[-1]))
        return pids
    except Exception:
        return []


app = Flask(__name__)
SESSIONS = {}
LOCK = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def clamp(v, lo, hi, default):
    try:
        v = int(v)
    except Exception:
        return default
    return max(lo, min(hi, v))


def mask_key(k):
    k = k or ""
    if len(k) <= 14:
        return k
    return k[:10] + "…" + k[-6:]


def event(msg, level="info"):
    e = {"t": now_iso(), "m": str(msg), "l": level}
    EVENTS.append(e)
    print(f"[event] {msg}", flush=True)


def load_store():
    global STORE
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("keys"), list):
            data["keys"] = [k for k in data["keys"] if isinstance(k, dict) and k.get("key")]
            opts = dict(DEFAULT_OPTIONS)
            opts.update(data.get("options") or {})
            data["options"] = opts
            STORE = data
            print("keystore: %d key(s) loaded" % len(STORE["keys"]), flush=True)
    except FileNotFoundError:
        pass
    except Exception as e:
        print("keystore load loi:", e, flush=True)


def save_store():
    try:
        tmp = KEYS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(STORE, f, ensure_ascii=False, indent=2)
        os.replace(tmp, KEYS_FILE)
    except Exception as e:
        print("keystore save loi:", e, flush=True)


def current_options():
    with KEYLOCK:
        return dict(STORE["options"])


def proxy_enabled():
    with KEYLOCK:
        return bool(STORE["options"].get("proxy", True))


def next_proxy_url():
    global _proxy_ix
    with PROXY_LOCK:
        p = PROXY_PORTS[_proxy_ix % len(PROXY_PORTS)]
        _proxy_ix += 1
    return "http://127.0.0.1:%d" % p


def http_req(method, url, headers=None, use_proxy=None, timeout=30, **kw):
    """HTTP request; neu bat proxy thi thu pool proxy IPv6 truoc, loi -> noi truc tiep."""
    if use_proxy is None:
        use_proxy = proxy_enabled()
    if use_proxy:
        px = next_proxy_url()
        try:
            r = requests.request(
                method,
                url,
                headers=headers,
                proxies={"http": px, "https": px},
                timeout=min(timeout, 12),
                **kw,
            )
            if r.status_code in (502, 503, 504):
                raise requests.exceptions.ProxyError("proxy tra loi %d" % r.status_code)
            with PROXY_LOCK:
                PROXY_STATS["via"] += 1
            return r
        except requests.exceptions.RequestException:
            with PROXY_LOCK:
                PROXY_STATS["fallback"] += 1
    return requests.request(method, url, headers=headers, timeout=timeout, **kw)


def ws_open(sess, url, **kw):
    """Mo WebSocket; neu bat proxy thi thu proxy truoc, loi -> noi truc tiep."""
    use = bool(sess.opts.get("proxy", proxy_enabled()))
    if use and getattr(sess, "_ws_proxy_bad", 0) < 3:
        try:
            return ws_connect(url, proxy=next_proxy_url(), **kw)
        except Exception:
            sess._ws_proxy_bad = getattr(sess, "_ws_proxy_bad", 0) + 1
            if sess._ws_proxy_bad == 1:
                sess.log("WS qua proxy loi -> ket noi truc tiep", "warn")
    return ws_connect(url, **kw)


def parse_key_tokens(text):
    out = []
    for part in re.split(r"[\s,;]+", text or ""):
        tok = part.strip().strip("\"'`,;.:")
        if not tok or tok.startswith("#") or len(tok) < 10:
            continue
        if "_" not in tok and len(tok) < 20:
            continue
        if tok not in out:
            out.append(tok)
    return out[:200]


def detect_platform(key):
    k = (key or "").strip()
    if k.startswith(("sfk_", "sfu_")):
        return "shardflux"
    if k.startswith("msk_"):
        return "miosa"
    if k.startswith("smk_"):
        return "smol"
    for pf, url in (
        ("shardflux", "https://api.shardflux.dev/v1/me"),
        ("miosa", "https://api.miosa.ai/api/v1/credits/balance"),
        ("smol", "https://api.smolmachines.com/v1/account"),
    ):
        try:
            r = http_req("GET", url, headers={"Authorization": "Bearer " + k}, timeout=10)
            if r.status_code == 200:
                return pf
        except requests.exceptions.RequestException:
            continue
    return None


def fetch_balance(platform, api_key, use_proxy=None):
    """tra ve {'text','exhausted','invalid'}; raise RuntimeError neu loi mang."""
    hdr = {"Authorization": "Bearer " + api_key, "User-Agent": UA["User-Agent"]}

    def get(url, timeout=20):
        return http_req("GET", url, headers=hdr, use_proxy=use_proxy, timeout=timeout)

    def bad(st):
        return {"text": "key khong hop le (%s)" % st, "exhausted": False, "invalid": True}

    if platform == "miosa":
        r = get("https://api.miosa.ai/api/v1/credits/balance")
        if r.status_code == 401:
            return bad(401)
        if r.status_code >= 400:
            raise RuntimeError("balance -> %d %s" % (r.status_code, r.text[:150]))
        try:
            bal = int(r.json().get("balance_credits") or 0)
        except Exception:
            raise RuntimeError("balance parse loi")
        return {"text": "%d credits" % bal, "exhausted": bal <= 0, "invalid": False}
    if platform == "smol":
        r = get("https://api.smolmachines.com/v1/account")
        if r.status_code == 401:
            return bad(401)
        if r.status_code >= 400:
            raise RuntimeError("account -> %d %s" % (r.status_code, r.text[:150]))
        try:
            d = r.json()
        except Exception:
            raise RuntimeError("account parse loi")
        pre = int(d.get("prepaidCreditMicros") or 0)
        pc = d.get("periodCost") or {}
        free_rem = max(0, int(pc.get("freeCreditMicros") or 0) - int(pc.get("creditAppliedMicros") or 0))
        budget = d.get("budgetRemainingMicros")
        budget = int(budget) if isinstance(budget, int) else 0
        total = pre + free_rem + max(0, budget)
        txt = "$%.2f" % (total / 1e6)
        if free_rem:
            txt += " (free $%.2f)" % (free_rem / 1e6)
        return {"text": txt, "exhausted": total <= 0, "invalid": False}
    r = get("https://api.shardflux.dev/v1/me")
    if r.status_code == 401:
        return bad(401)
    if r.status_code >= 400:
        raise RuntimeError("/me -> %d %s" % (r.status_code, r.text[:150]))
    try:
        me = r.json()
    except Exception:
        raise RuntimeError("/me parse loi")
    orgs = me.get("memberships") or []
    if not orgs:
        return {"text": "khong co org", "exhausted": False, "invalid": False}
    org = orgs[0].get("organization_id")
    r2 = get("https://api.shardflux.dev/v1/organizations/%s/usage/summary" % org)
    if r2.status_code == 401:
        return bad(401)
    if r2.status_code >= 400:
        raise RuntimeError("usage -> %d %s" % (r2.status_code, r2.text[:150]))
    try:
        u = r2.json()
    except Exception:
        raise RuntimeError("usage parse loi")
    # --- kiem tra CPU-h (miễn phí) thay vi balance tien ---
    cpu_used = 0.0
    for key in ("cpu_hours_used", "cpuHours", "cpu_hours", "used_cpu_hours",
                "cpu_usage_hours", "cpuHoursUsed"):
        v = u.get(key)
        if isinstance(v, (int, float)):
            cpu_used = float(v)
            break
    if cpu_used == 0.0:
        # thu trong cac trung tam co the khac nhau
        for section in ("usage", "resources", "compute", "cpu"):
            sec = u.get(section)
            if isinstance(sec, dict):
                for key in ("cpu_hours_used", "cpuHours", "cpu_hours", "used_cpu_hours",
                            "cpu_usage_hours", "cpuHoursUsed"):
                    v = sec.get(key)
                    if isinstance(v, (int, float)):
                        cpu_used = float(v)
                        break
                if cpu_used > 0:
                    break
    cpu_limit = 500.0
    for key in ("cpu_hours_limit", "cpuHoursLimit", "cpu_limit", "cpuHours"):
        v = u.get(key)
        if isinstance(v, (int, float)):
            cpu_limit = float(v)
            break
    ex = bool(u.get("allowance_exhausted")) or bool(u.get("exhausted")) or cpu_used >= cpu_limit
    plan = (u.get("plan") or {}).get("plan_key") or "?"
    txt = "%.1f / %.0f CPU-h · %s" % (cpu_used, cpu_limit, plan)
    if ex:
        txt += " (HẾT CPU-h)"
    return {"text": txt, "exhausted": ex, "invalid": False,
            "cpu_used": cpu_used, "cpu_limit": cpu_limit}


load_store()


class Session:
    def __init__(self, platform, api_key, resource_id, opts):
        self.sid = secrets.token_hex(4)
        self.platform = platform
        self.api_key = api_key.strip()
        self.resource_id = resource_id.strip()
        self.opts = opts
        self.stop_evt = threading.Event()
        self.logs = deque(maxlen=400)
        self.status = {
            "phase": "starting",
            "resource_state": "?",
            "last_ok": None,
            "last_action": "",
            "last_error": "",
            "ticks": 0,
            "errors": 0,
            "started_at": now_iso(),
            "ws": "off",
        }
        self._token_cache = {}
        self._ws_close = None
        self.threads = []

    def log(self, msg, level="info"):
        line = f"[{now_iso()}] {msg}"
        self.logs.append({"t": line, "l": level})
        print(f"{self.platform}/{self.sid} {line}", flush=True)

    def set(self, **kw):
        self.status.update(kw)

    def start(self):
        t = threading.Thread(target=self._tick_loop, daemon=True)
        t.start()
        self.threads.append(t)
        if self.opts.get("ws_attach") and WS_OK:
            tw = threading.Thread(target=self._ws_loop, daemon=True)
            tw.start()
            self.threads.append(tw)

    def stop(self):
        self.stop_evt.set()
        cl = self._ws_close
        if cl:
            try:
                cl()
            except Exception:
                pass

    def _tick_loop(self):
        self.set(phase="running")
        interval = clamp(self.opts.get("interval"), 10, 86400, 60)
        backoff = interval
        try:
            self.setup()
        except Exception as e:
            self.log(f"setup lỗi: {e}", "error")
        while not self.stop_evt.is_set():
            try:
                self.tick()
                self.set(phase="running", last_ok=now_iso(), last_error="")
                backoff = interval
            except Exception as e:
                self.status["errors"] += 1
                self.set(last_error=str(e)[:300])
                self.log(f"tick lỗi: {e}", "error")
                backoff = min(max(interval, 15) * (2 ** min(self.status["errors"], 5)), 300)
            self.status["ticks"] += 1
            self.stop_evt.wait(backoff)

    def _ws_loop(self):
        while not self.stop_evt.is_set():
            try:
                self.ws_run()
                self.stop_evt.wait(5)
            except Exception as e:
                if self.stop_evt.is_set():
                    break
                msg = str(e)
                self.set(ws=f"reconnect: {msg[:80]}")
                self.log(f"WS lỗi: {msg[:200]}", "warn")
                if "1011" in msg or "connection failed" in msg.lower():
                    self.stop_evt.wait(300)
                else:
                    self.stop_evt.wait(10)

    def api(self, method, url, base=None, **kw):
        headers = kw.pop("headers", {})
        headers.setdefault("User-Agent", UA["User-Agent"])
        if self.api_key:
            headers.setdefault("Authorization", f"Bearer {self.api_key}")
        r = http_req(method, url, headers=headers, timeout=30, **kw)
        if r.status_code >= 400:
            body = r.text[:300]
            raise RuntimeError(f"{method} {url.split('?')[0]} -> {r.status_code} {body}")
        if "application/json" in r.headers.get("content-type", ""):
            return r.json()
        return r.text

    def setup(self):
        pass

    def tick(self):
        pass

    def ws_run(self):
        pass


class ShardfluxSession(Session):
    BASE = "https://api.shardflux.dev/v1"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._token_lock = threading.Lock()

    def _invalidate_token(self):
        """Hủy token tool đang cache để lần sau lấy token mới (dùng sau khi epoch thay đổi)."""
        with self._token_lock:
            self._token_cache = {}

    def _api_with_tok(self, method, url, json=None, headers=None, **kw):
        """Goi API can tool token; neu bi stale_epoch thi bo token cu, lay token moi va thu lai 1 lan."""
        h = dict(headers or {})
        last_err = None
        for _ in range(2):
            tok = self._tool_token()
            h["Authorization"] = f"Bearer {tok}"
            try:
                return self.api(method, url, json=json, headers=h, **kw)
            except RuntimeError as e:
                last_err = e
                if "stale_epoch" in str(e):
                    self._invalidate_token()
                    continue
                raise
        raise last_err

    def setup(self):
        me = self.api("GET", f"{self.BASE}/me")
        name = me.get("key", {}).get("name") or me.get("email") or me.get("id", "")
        self.log(f"đăng nhập OK ({name})")
        ws = self.api("GET", f"{self.BASE}/workspaces/{self.resource_id}")
        key = ws.get("workspace_key", self.resource_id)
        self.log(f"workspace '{key}' state={ws.get('observed_state')}")
        try:
            self.api(
                "PUT",
                f"{self.BASE}/workspaces/{self.resource_id}/idle-policy",
                json={"idle_policy": "never"},
            )
            self.log("idle_policy = never (không bao giờ tự suspend)")
        except Exception as e:
            self.log(f"set idle_policy never thất bại: {e}", "warn")
        try:
            self.api("DELETE", f"{self.BASE}/workspaces/{self.resource_id}/suspend-when-idle")
            self.log("đã hủy suspend-when-idle đang chờ (nếu có)")
        except Exception as e:
            self.log(f"hủy suspend-when-idle: {e}", "warn")

    def _tool_token(self):
        with self._token_lock:
            c = self._token_cache
            if c.get("token") and c.get("exp", 0) - time.time() > 300:
                return c["token"]
            data = self.api(
                "POST",
                f"{self.BASE}/workspaces/{self.resource_id}/tool-tokens",
                json={"agent_label": "terminal-keeper", "tools": ["pty", "files"]},
            )
            exp = time.time() + 900
            try:
                from datetime import datetime as _dt

                exp = _dt.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp()
            except Exception:
                pass
            self._token_cache = {"token": data["token"], "exp": exp}
            return data["token"]

    def tick(self):
        ws = self.api("GET", f"{self.BASE}/workspaces/{self.resource_id}")
        state = ws.get("observed_state")
        self.set(resource_state=state)
        cell = ws.get("cell_endpoint")
        if state == "suspended" and self.opts.get("auto_resume", True):
            self.log("workspace suspended -> resume", "warn")
            self.api(
                "POST",
                f"{self.BASE}/workspaces/{self.resource_id}/resume",
                json={"agent_label": "terminal-keeper"},
                headers={"Prefer": "wait=20"},
            )
            # Sau khi resume, epoch cua workspace thay doi -> bo token cu de lay token moi.
            self._invalidate_token()
            ws = self.api("GET", f"{self.BASE}/workspaces/{self.resource_id}")
            state = ws.get("observed_state")
            cell = ws.get("cell_endpoint")
            self.set(resource_state=state)
        if not cell:
            raise RuntimeError(f"workspace chưa chạy (state={state}), chưa có cell_endpoint")
        try:
            sec = clamp(self.opts.get("keepalive_sec"), 60, 43200, 1800)
            self._api_with_tok(
                "POST",
                f"{cell}/v1/workspaces/{self.resource_id}/keepalive",
                json={"seconds": sec},
            )
            self.set(last_action=f"keepalive {sec}s")
            try:
                idle = self._api_with_tok(
                    "GET",
                    f"{cell}/v1/workspaces/{self.resource_id}/idle",
                )
                sa = idle.get("suspend_at")
                if sa:
                    self.set(last_action=f"keepalive {sec}s | suspend_at={sa}")
            except Exception:
                pass
        except RuntimeError as e:
            # Neu loi stale_epoch ke tiep, bo token va kiem tra lai trang thai workspace de danh bao chinh xac.
            if "stale_epoch" in str(e):
                self._invalidate_token()
            raise

    def ws_run(self):
        # Doi den khi workspace chay moi duoc phep gan PTY (tranh loi workspace_not_running sau resume).
        for _ in range(12):
            if self.stop_evt.is_set():
                return
            info = self.api("GET", f"{self.BASE}/workspaces/{self.resource_id}")
            state = info.get("observed_state")
            cell = info.get("cell_endpoint")
            if state == "running" and cell:
                break
            self.log(f"workspace chưa sẵn sàng (state={state}), chờ 2s...", "warn")
            self.stop_evt.wait(2)
        else:
            raise RuntimeError(f"workspace không chạy sau chờ (state={state})")
        # Invalidate token tai day de khong bao gio su dung token bi stale sau mot lan resume gan day.
        self._invalidate_token()
        tok = self._tool_token()
        sid = f"keeper-{self.sid}"
        self._api_with_tok(
            "POST",
            f"{cell}/v1/workspaces/{self.resource_id}/pty",
            json={"session_id": sid, "rows": 24, "cols": 80},
        )
        offset = 0
        try:
            st = self._api_with_tok(
                "GET",
                f"{cell}/v1/workspaces/{self.resource_id}/pty/{sid}",
            )
            offset = st.get("output_size", 0)
        except Exception:
            pass
        url = (
            f"{cell.replace('https://', 'wss://')}/v1/workspaces/{self.resource_id}"
            f"/pty/{sid}/attach?offset={offset}"
        )
        self.set(ws="connecting")
        with ws_open(
            self,
            url,
            additional_headers={"Authorization": f"Bearer {tok}"},
            open_timeout=20,
            close_timeout=5,
            ping_interval=20,
            ping_timeout=20,
        ) as wsc:
            self._ws_close = wsc.close
            self.set(ws="attached")
            self.log("PTY WebSocket đã gắn (terminal sống trên cloud)")
            while not self.stop_evt.is_set():
                try:
                    wsc.recv(timeout=5)
                except TimeoutError:
                    continue
        self.set(ws="closed")


class MiosaSession(Session):
    BASE = "https://api.miosa.ai/api/v1"

    def setup(self):
        items = self.api("GET", f"{self.BASE}/sandboxes")
        data = items.get("data", []) if isinstance(items, dict) else []
        sb = None
        for s in data:
            if s.get("id") == self.resource_id:
                sb = s
                break
        if sb is None:
            sb = self.api("GET", f"{self.BASE}/sandboxes/{self.resource_id}")
        self.log(
            f"sandbox '{sb.get('name') or sb.get('slug')}' state={sb.get('state')} "
            f"timeout_sec={sb.get('timeout_sec')} idle={sb.get('idle_timeout_sec')}"
        )
        r = self.api(
            "PATCH",
            f"{self.BASE}/sandboxes/{self.resource_id}",
            json={
                "always_on": True,
                "idle_timeout_sec": 0,
                "timeout_sec": 86400,
            },
        )
        self.log(
            f"always_on={r.get('always_on')} idle_timeout_sec={r.get('idle_timeout_sec')} "
            f"timeout_sec={r.get('timeout_sec')}"
        )

    def tick(self):
        sb = self.api("GET", f"{self.BASE}/sandboxes/{self.resource_id}")
        state = sb.get("state")
        self.set(resource_state=state)
        if state in ("paused", "stopped") and self.opts.get("auto_resume", True):
            self.log(f"sandbox {state} -> resume", "warn")
            self.api("POST", f"{self.BASE}/sandboxes/{self.resource_id}/resume")
            state = "running"
            self.set(resource_state=state)
        if state == "running":
            self.api(
                "POST",
                f"{self.BASE}/sandboxes/{self.resource_id}/extend",
                json={"timeout_sec": 86400},
            )
            self.set(last_action="extend timeout 86400s")
            if self.opts.get("activity_ping"):
                self.api(
                    "POST",
                    f"{self.BASE}/sandboxes/{self.resource_id}/exec",
                    json={"command": "true", "timeout": 10},
                )
                self.set(last_action="extend + exec ping")
        elif state in ("creating", "provisioning"):
            self.set(last_action="đang chờ sandbox chạy")
        else:
            raise RuntimeError(f"sandbox state={state}")

    def _close_term(self, sid):
        try:
            self.api("DELETE", f"{self.BASE}/sandboxes/{self.resource_id}/terminal/{sid}")
            self.log(f"đã đóng terminal session {sid} (tránh tồn đọng)")
        except Exception:
            pass

    def ws_run(self):
        old = getattr(self, "_term_sid", None)
        if old:
            self._close_term(old)
            self._term_sid = None
        term = self.api(
            "POST",
            f"{self.BASE}/sandboxes/{self.resource_id}/terminal",
            json={"cols": 80, "rows": 24},
        )
        self._term_sid = term["session_id"]
        ws_url = term["ws_url"]
        if "?" in ws_url:
            url = f"{ws_url}&token={term['stream_auth']}"
        else:
            url = f"{ws_url}?token={term['stream_auth']}"
        self.set(ws="connecting")
        try:
            with ws_open(
                self,
                url,
                origin="https://miosa.ai",
                open_timeout=20,
                close_timeout=5,
                ping_interval=20,
                ping_timeout=20,
            ) as wsc:
                self._ws_close = wsc.close
                self.set(ws="attached")
                self.log(f"Terminal WebSocket đã gắn (session {self._term_sid})")
                while not self.stop_evt.is_set():
                    try:
                        wsc.recv(timeout=5)
                    except TimeoutError:
                        continue
            self.set(ws="closed")
        finally:
            sid = self._term_sid
            self._term_sid = None
            if sid:
                self._close_term(sid)


class SmolSession(Session):
    BASE = "https://api.smolmachines.com/v1"

    def setup(self):
        m = self.api("GET", f"{self.BASE}/machines/{self.resource_id}")
        self.log(
            f"machine '{m.get('name') or m.get('id')}' state={m.get('state')} "
            f"autoStopSeconds={m.get('autoStopSeconds')}"
        )
        if m.get("state") != "started" and self.opts.get("auto_resume", True):
            self.api("POST", f"{self.BASE}/machines/{self.resource_id}/start")
            self.log("đã start machine")

    def tick(self):
        m = self.api("GET", f"{self.BASE}/machines/{self.resource_id}")
        state = m.get("state")
        self.set(resource_state=state)
        if state != "started":
            if self.opts.get("auto_resume", True):
                self.log(f"machine {state} -> start", "warn")
                self.api("POST", f"{self.BASE}/machines/{self.resource_id}/start")
                self.set(resource_state="started")
            else:
                raise RuntimeError(f"machine state={state}")
        self.api(
            "POST",
            f"{self.BASE}/machines/{self.resource_id}/exec",
            json={"command": "true", "timeoutSeconds": 15},
        )
        self.set(last_action="exec ping (reset lastActivityAt, auto-start nếu dừng)")

    def ws_run(self):
        from urllib.parse import quote

        url = (
            f"wss://api.smolmachines.com/v1/machines/{self.resource_id}"
            f"/exec/interactive?cmd=%2Fbin%2Fsh&cols=80&rows=24"
            f"&access_token={quote(self.api_key, safe='')}"
        )
        self.set(ws="connecting")
        with ws_open(
            self,
            url,
            origin="https://smolmachines.com",
            open_timeout=20,
            close_timeout=5,
            ping_interval=20,
            ping_timeout=20,
        ) as wsc:
            self._ws_close = wsc.close
            self.set(ws="attached")
            self.log("Shell WebSocket đã gắn (/bin/sh sống trên máy ảo)")
            while not self.stop_evt.is_set():
                try:
                    wsc.recv(timeout=5)
                except TimeoutError:
                    continue
        self.set(ws="closed")


PLATFORMS = {
    "shardflux": ShardfluxSession,
    "miosa": MiosaSession,
    "smol": SmolSession,
}


def list_resources(platform, api_key):
    cls = PLATFORMS.get(platform)
    if not cls:
        raise RuntimeError("platform không hợp lệ")
    tmp = cls(platform, api_key, "", {})
    if platform == "shardflux":
        data = tmp.api("GET", f"{cls.BASE}/workspaces?limit=200")
        items = data.get("data", data if isinstance(data, list) else [])
        return [
            {
                "id": w.get("id"),
                "label": f"{w.get('workspace_key') or w.get('id')} · {w.get('observed_state')}",
            }
            for w in items
        ]
    if platform == "miosa":
        data = tmp.api("GET", f"{cls.BASE}/sandboxes")
        items = data.get("data", []) if isinstance(data, dict) else data
        return [
            {
                "id": s.get("id"),
                "label": f"{s.get('name') or s.get('slug') or s.get('id')} · {s.get('state')}",
            }
            for s in items
        ]
    data = tmp.api("GET", f"{cls.BASE}/machines")
    items = data if isinstance(data, list) else data.get("data", [])
    return [
        {
            "id": m.get("id"),
            "label": f"{m.get('name') or m.get('id')} · {m.get('state')}",
        }
        for m in items
    ]


def spawn_session(platform, api_key, resource_id, opts):
    resource_id = (resource_id or "").strip()
    with LOCK:
        for s in SESSIONS.values():
            if s.platform == platform and s.resource_id == resource_id and not s.stop_evt.is_set():
                return None
        sess = PLATFORMS[platform](platform, api_key, resource_id, opts)
        SESSIONS[sess.sid] = sess
    sess.log(f"BẬT keep-alive cho {platform} / {resource_id}")
    sess.start()
    return sess


def stop_key_sessions(api_key, reason=""):
    n = 0
    for s in list(SESSIONS.values()):
        if s.api_key == api_key:
            with LOCK:
                SESSIONS.pop(s.sid, None)
            s.stop()
            s.log(f"ĐÃ DỪNG ({reason})" if reason else "ĐÃ DỪNG", "warn")
            n += 1
    return n


def remove_key(api_key, reason="", platform=None):
    # Neu xoa vi het CPU-h (shardflux): tat / xoa may (workspace) truoc khi xoa key kho.
    if platform == "shardflux":
        try:
            items = list_resources("shardflux", api_key)
        except Exception:
            items = []
        hdr = {"Authorization": "Bearer " + api_key, "User-Agent": UA["User-Agent"]}
        for it in items:
            rid = it.get("id")
            if not rid:
                continue
            try:
                # Thu suspend truoc, neu khong co API thi xoa workspace
                requests.post(
                    "https://api.shardflux.dev/v1/workspaces/%s/suspend" % rid,
                    headers=hdr, timeout=15,
                )
            except Exception:
                pass
            try:
                requests.delete(
                    "https://api.shardflux.dev/v1/workspaces/%s" % rid,
                    headers=hdr, timeout=15,
                )
            except Exception:
                pass
    with KEYLOCK:
        before = len(STORE["keys"])
        STORE["keys"] = [k for k in STORE["keys"] if k.get("key") != api_key]
        removed = len(STORE["keys"]) < before
        if removed:
            save_store()
        KEYINFO.pop(api_key, None)
    n = stop_key_sessions(api_key, reason or "xóa key")
    if removed:
        event(f"đã xóa key {mask_key(api_key)} ({reason}) — dừng {n} phiên", "warn")
    return removed, n


def start_key(api_key, opts=None):
    """chay toan bo may cua key. tra ve {machines, started} hoac {error}"""
    with KEYLOCK:
        rec = next((k for k in STORE["keys"] if k.get("key") == api_key), None)
    if not rec:
        return {"error": "key không có trong kho"}
    platform = rec.get("platform")
    if platform not in PLATFORMS:
        return {"error": f"platform không hợp lệ: {platform}"}
    opts = opts or current_options()
    try:
        items = list_resources(platform, api_key)
    except Exception as e:
        return {"error": str(e)[:300]}
    started = 0
    for it in items:
        if spawn_session(platform, api_key, it["id"], opts):
            started += 1
    with KEYLOCK:
        info = KEYINFO.setdefault(api_key, {})
        info["machines"] = [i["label"] for i in items]
        info.setdefault("last_check", now_iso())
    return {"machines": len(items), "started": started}


def refresh_key_balance(api_key, platform=None, update_machines=False):
    """cap nhat balance (+ danh sach may). tra ve balance dict; None neu loi mang."""
    if not platform:
        with KEYLOCK:
            rec = next((k for k in STORE["keys"] if k.get("key") == api_key), None)
        platform = rec.get("platform") if rec else None
    if not platform:
        return None
    try:
        bal = fetch_balance(platform, api_key)
    except Exception as e:
        with KEYLOCK:
            info = KEYINFO.setdefault(api_key, {})
            info["error"] = str(e)[:200]
            info["last_check"] = now_iso()
        return None
    with KEYLOCK:
        info = KEYINFO.setdefault(api_key, {})
        info["balance"] = bal
        info["error"] = ""
        info["last_check"] = now_iso()
    if not (bal.get("exhausted") or bal.get("invalid")) and update_machines:
        try:
            items = list_resources(platform, api_key)
            with KEYLOCK:
                KEYINFO.setdefault(api_key, {})["machines"] = [i["label"] for i in items]
        except Exception as e:
            with KEYLOCK:
                KEYINFO.setdefault(api_key, {})["error"] = str(e)[:200]
    return bal


def balance_monitor_loop():
    time.sleep(10)
    cycle = 0
    while True:
        cycle += 1
        with KEYLOCK:
            recs = [dict(k) for k in STORE["keys"]]
        for rec in recs:
            k = rec.get("key")
            if not k:
                continue
            bal = refresh_key_balance(k, rec.get("platform"), update_machines=(cycle % 5 == 1))
            if bal is None:
                continue
            if bal.get("invalid"):
                remove_key(k, "key không hợp lệ (401)", rec.get("platform"))
            elif bal.get("exhausted"):
                remove_key(k, "hết CPU-h (%.1f/%.0f)" % (bal.get("cpu_used", 0), bal.get("cpu_limit", 500)), rec.get("platform"))
        time.sleep(60)


def autostart_loop():
    time.sleep(3)
    with KEYLOCK:
        auto = bool(STORE["options"].get("auto_start", True))
        keys = [k.get("key") for k in STORE["keys"] if k.get("key")]
    if not keys:
        return
    if not auto:
        event(f"bỏ qua {len(keys)} key đã lưu (tự chạy khi mở app đang tắt)")
        return
    opts = current_options()
    ok = err = 0
    for k in keys:
        r = start_key(k, opts)
        if "error" in r:
            err += 1
            event(f"tự chạy {mask_key(k)} lỗi: {r['error']}", "error")
        else:
            ok += 1
            event(f"tự chạy {mask_key(k)}: {r['machines']} máy, {r['started']} phiên mới", "info")
    if ok or err:
        msg = f"khởi động xong: {ok} key OK" + (f", {err} lỗi" if err else "")
        event(msg, "warn" if err else "info")


HTML = r"""<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Terminal Keeper</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--fg:#e6edf3;--mut:#8b949e;--ac:#2f81f7;--ok:#3fb950;--err:#f85149;--warn:#d29922}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
header{padding:14px 20px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:14px;flex-wrap:wrap}
header h1{font-size:18px;margin:0}
.badge{font-size:12px;padding:2px 8px;border-radius:10px;background:#1f6feb33;color:var(--ac);border:1px solid #1f6feb66}
.badge.bg{background:#23863633;color:var(--ok);border-color:#23863666}
main{padding:16px 20px;max-width:1200px;margin:0 auto}
.tabs{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.tab{padding:8px 16px;border:1px solid var(--bd);border-radius:8px;background:var(--card);cursor:pointer;color:var(--mut)}
.tab.on{border-color:var(--ac);color:var(--fg);background:#1f6feb22}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px;margin-bottom:16px}
.card h2{margin:0 0 4px;font-size:15px}
.hint{color:var(--mut);font-size:12.5px;margin-bottom:10px}
label{display:block;font-size:12px;color:var(--mut);margin:10px 0 4px}
input,select,button{font:inherit}
input[type=text],input[type=password],input[type=number]{width:100%;padding:8px 10px;background:#0d1117;border:1px solid var(--bd);border-radius:6px;color:var(--fg)}
textarea{width:100%;padding:9px 10px;background:#0d1117;border:1px solid var(--bd);border-radius:6px;color:var(--fg);font:12.5px/1.5 Consolas,monospace;resize:vertical}
.evb{background:#010409;border:1px solid var(--bd);border-radius:8px;padding:10px;height:130px;overflow:auto;font:12px/1.7 Consolas,monospace}
.evb .error{color:var(--err)}.evb .warn{color:var(--warn)}.evb .info{color:var(--mut)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
.row>div{flex:1;min-width:150px}
button{padding:8px 14px;border-radius:6px;border:1px solid var(--bd);background:#21262d;color:var(--fg);cursor:pointer}
button:hover{border-color:var(--mut)}
button.primary{background:#238636;border-color:#238636}
button.primary:hover{background:#2ea043}
button.danger{background:#da3633;border-color:#da3633}
button.blue{background:#1f6feb;border-color:#1f6feb}
button:disabled{opacity:.5;cursor:not-allowed}
.msg{margin-top:8px;font-size:13px;white-space:pre-wrap}
.msg.err{color:var(--err)}.msg.ok{color:var(--ok)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
th{color:var(--mut);font-weight:600}
.pill{font-size:11px;padding:1px 8px;border-radius:9px;border:1px solid var(--bd)}
.pill.ok{color:var(--ok);border-color:#23863666;background:#23863622}
.pill.err{color:var(--err);border-color:#da363366;background:#da363322}
.pill.warn{color:var(--warn);border-color:#9e6a0366;background:#9e6a0322}
#logbox{background:#010409;border:1px solid var(--bd);border-radius:8px;padding:10px;height:260px;overflow:auto;font:12px/1.6 Consolas,monospace;white-space:pre-wrap}
.lw .error{color:var(--err)}.lw .warn{color:var(--warn)}
details{margin-top:10px}summary{cursor:pointer;color:var(--ac);font-size:13px}
code{background:#21262d;padding:1px 5px;border-radius:4px;font-size:12.5px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px}
.cb{display:flex;align-items:center;gap:7px;margin-top:12px;font-size:13px}
.cb input{width:auto}
.hidden{display:none}
</style>
</head>
<body>
<header>
  <h1>Terminal Keeper</h1>
  <span class="badge" id="ver">v?</span>
  <span class="badge" id="mode">foreground</span>
  <span class="badge bg" id="wsmod">websocket: ...</span>
  <div style="margin-left:auto;display:flex;gap:8px">
    <button id="btnBg" class="blue">Chạy nền (đóng terminal vẫn sống)</button>
    <button id="btnOff" class="danger">Tắt app nền</button>
  </div>
</header>
<main>
<div class="card" style="padding:10px 16px">
  <div id="banner" class="msg warn" style="color:var(--warn)"></div>
</div>

<div class="card">
  <h2>Nhập API key hàng loạt</h2>
  <div class="hint">Mỗi dòng 1 key (hoặc cách nhau bởi space/dấu phẩy) — <b>tự nhận diện nền tảng</b> theo tiền tố <code>sfk_</code>/<code>sfu_</code>=shardflux, <code>msk_</code>=miosa, <code>smk_</code>=smol. Sau khi thêm: tự tải <b>tất cả máy</b> của key và bật keepalive. Key đã lưu sẽ tự chạy lại khi mở app, tự xóa nếu hết balance.</div>
  <textarea id="keysIn" rows="4" spellcheck="false" placeholder="sfk_xxx&#10;msk_yyy&#10;smk_zzz"></textarea>
  <div class="grid" style="margin-top:12px">
    <div><label>Chu kỳ kiểm tra (giây, tối thiểu 10)</label><input type="number" id="gInterval" value="60" min="10"></div>
    <div><label>Keepalive seconds (shardflux)</label><input type="number" id="gKeep" value="1800" min="60" max="43200"></div>
    <div>
      <label>Giới hạn</label>
      <div class="cb"><input type="checkbox" id="gProxy" checked><span>Dùng proxy IPv6 (127.0.0.1:2000-2199)</span></div>
      <div class="cb"><input type="checkbox" id="gWs" checked><span>Gắn WebSocket giữ terminal</span></div>
      <div class="cb"><input type="checkbox" id="gResume" checked><span>Tự resume/start nếu bị pause</span></div>
      <div class="cb"><input type="checkbox" id="gPing"><span>Thêm exec ping mỗi chu kỳ (miosa)</span></div>
      <div class="cb"><input type="checkbox" id="gAuto" checked><span>Tự chạy key đã lưu khi mở app</span></div>
    </div>
  </div>
  <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap">
    <button id="btnAdd" class="primary">Thêm key &amp; tự chạy tất cả máy</button>
    <button id="btnBal" class="blue">Làm mới balance</button>
    <button id="btnStartAll" class="blue">Chạy tất cả</button>
    <button id="btnStopAll">Dừng tất cả</button>
  </div>
  <div class="msg" id="addMsg"></div>
</div>

<div class="card">
  <h2>Dashboard</h2>
  <div class="hint" id="sumLine">—</div>
  <div class="grid" id="statsBox" style="margin-top:6px"></div>
</div>

<div class="card">
  <h2>Key đã lưu</h2>
  <table>
    <thead><tr><th>Key</th><th>Nền tảng</th><th>Máy</th><th>Phiên</th><th>Balance</th><th>Kiểm tra lúc</th><th>Trạng thái</th><th></th></tr></thead>
    <tbody id="keysBody"><tr><td colspan="8" style="color:var(--mut)">chưa có key nào — dán key vào ô trên</td></tr></tbody>
  </table>
</div>

<div class="card lw">
  <h2>Sự kiện</h2>
  <div class="evb" id="evBox"><div style="color:var(--mut)">chưa có sự kiện</div></div>
</div>

<details>
  <summary>Thêm thủ công từng resource (nâng cao)</summary>
  <div class="tabs" style="margin-top:12px">
    <div class="tab on" data-t="shardflux">shardflux.dev</div>
    <div class="tab" data-t="miosa">miosa.ai</div>
    <div class="tab" data-t="smol">smolmachines.com</div>
  </div>

  <div class="card" id="panel" style="margin-top:10px">
    <h2 id="pTitle"></h2>
    <div class="hint" id="pHint"></div>

    <div class="row">
      <div style="flex:3">
        <label>API key (dán vào đây)</label>
        <input type="password" id="apiKey" placeholder="sfk_... / msk_... / smk_...">
      </div>
      <div style="flex:0 0 auto;padding-bottom:2px">
        <button id="btnList" class="blue">Kiểm tra &amp; tải danh sách</button>
      </div>
    </div>

    <div class="row">
      <div>
        <label>Resource (chọn hoặc dán ID)</label>
        <select id="resSel" style="width:100%;padding:8px;background:#0d1117;border:1px solid var(--bd);border-radius:6px;color:var(--fg)">
          <option value="">— bấm "tải danh sách" trước —</option>
        </select>
      </div>
      <div>
        <label>hoặc ID thủ công</label>
        <input type="text" id="resId" placeholder="uuid / mach-... (tự điền khi chọn)">
      </div>
    </div>

    <div class="grid">
      <div>
        <label>Chu kỳ kiểm tra (giây, tối thiểu 10)</label>
        <input type="number" id="optInterval" value="60" min="10">
      </div>
      <div>
        <label>Keepalive seconds (shardflux)</label>
        <input type="number" id="optKeep" value="1800" min="60" max="43200">
      </div>
      <div>
        <label>Giới hạn</label>
        <div class="cb"><input type="checkbox" id="optResume" checked><span>Tự resume/start nếu bị pause</span></div>
        <div class="cb"><input type="checkbox" id="optWs" checked><span>Gắn WebSocket giữ terminal</span></div>
        <div class="cb" id="cbPing" style="display:none"><input type="checkbox" id="optPing"><span>Thêm exec ping mỗi chu kỳ</span></div>
      </div>
    </div>

    <div style="margin-top:14px;display:flex;gap:10px">
      <button id="btnStart" class="primary">BẬT giữ sống</button>
      <span class="msg" id="startMsg"></span>
    </div>

    <details id="helpBox">
      <summary>Cách lấy API key từng nền tảng</summary>
      <div class="hint" id="helpText"></div>
    </details>
  </div>
</details>

<div class="card">
  <h2>Phiên đang chạy</h2>
  <table>
    <thead><tr><th>ID</th><th>Nền tảng</th><th>Resource</th><th>Trạng thái</th><th>Hành động cuối</th><th>Lỗi</th><th>WS</th><th></th></tr></thead>
    <tbody id="sessBody"><tr><td colspan="8" style="color:var(--mut)">chưa có phiên nào</td></tr></tbody>
  </table>
</div>

<div class="card lw">
  <h2>Log</h2>
  <div class="row" style="margin-bottom:8px">
    <div><select id="logSel" style="width:100%;padding:7px;background:#0d1117;border:1px solid var(--bd);border-radius:6px;color:var(--fg)"><option value="">— chọn phiên —</option></select></div>
  </div>
  <div id="logbox"></div>
</div>
</main>

<script>
const P = {
 shardflux:{title:"Shardflux — cloud workspace",ph:"sfk_<keyid>_<secret> (hoặc sfu_...): console app.shardflux.dev → Project → API keys → Create",
  hint:"Cơ chế: PUT idle-policy=never + POST keepalive (tối đa 12h/lần) trên cell + tự resume. Workspace: Ubuntu cloud, terminal qua PTY WebSocket.",
  help:"1. Vào app.shardflux.dev → mở project → mục API keys → Create key.<br>2. Copy khóa dạng <code>sfk_...</code> (hiện 1 lần).<br>3. Dán vào ô trên → 'Kiểm tra & tải danh sách'."},
 miosa:{title:"MIOSA — sandbox Firecracker",ph:"msk_... (MIOSA API key)",
  hint:"Cơ chế: PATCH always_on=true + idle_timeout_sec=0 + timeout_sec=86400, mỗi chu kỳ POST extend, tự resume khi paused.",
  help:"1. Vào miosa.ai console → Settings → API keys → tạo key dạng <code>msk_...</code>.<br>2. Dán vào ô trên → 'Kiểm tra & tải danh sách'."},
 smol:{title:"Smol Machines — microVM",ph:"smk_... (hoặc access token Auth0)",
  hint:"Cơ chế: mỗi chu kỳ GET state + POST exec 'true' (tự start lại máy đã dừng, reset lastActivityAt). Máy có autoStopSeconds=null là không tự dừng.",
  help:"1. Vào smolmachines.com console → Settings → API keys → tạo key dạng <code>smk_...</code> (cần quyền owner/admin).<br>2. Dán vào ô trên → 'Kiểm tra & tải danh sách'."}
};
let cur = "shardflux";
const $ = id => document.getElementById(id);

function setTab(t){
  cur = t;
  document.querySelectorAll(".tab").forEach(e=>e.classList.toggle("on", e.dataset.t===t));
  $("pTitle").textContent = P[t].title;
  $("pHint").textContent = P[t].hint;
  $("apiKey").placeholder = P[t].ph;
  $("helpText").innerHTML = P[t].help;
  $("cbPing").style.display = t==="miosa" ? "" : "none";
  $("optKeep").disabled = t!=="shardflux";
  $("startMsg").textContent = ""; $("startMsg").className = "msg";
}
document.querySelectorAll(".tab").forEach(e=>e.onclick=()=>setTab(e.dataset.t));

$("btnList").onclick = async ()=>{
  const key = $("apiKey").value.trim();
  const msg = $("startMsg"); msg.className="msg"; msg.textContent="đang kiểm tra...";
  try{
    const r = await fetch("/api/list",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({platform:cur,api_key:key})});
    const j = await r.json();
    if(!j.ok) throw new Error(j.error);
    const sel = $("resSel"); sel.innerHTML="";
    if(!j.items.length){ sel.innerHTML='<option value="">(trống)</option>'; }
    j.items.forEach(it=>{
      const o=document.createElement("option"); o.value=it.id; o.textContent=it.label; sel.appendChild(o);
    });
    if(j.items.length){ sel.value=j.items[0].id; $("resId").value=j.items[0].id; }
    msg.className="msg ok"; msg.textContent=`OK — ${j.items.length} resource(s)`;
  }catch(e){ msg.className="msg err"; msg.textContent="LỖI: "+e.message; }
};
$("resSel").onchange = ()=>{ $("resId").value = $("resSel").value; };

$("btnStart").onclick = async ()=>{
  const msg = $("startMsg");
  const rid = $("resId").value.trim() || $("resSel").value;
  if(!$("apiKey").value.trim() || !rid){ msg.className="msg err"; msg.textContent="cần API key + resource ID"; return; }
  msg.className="msg"; msg.textContent="đang khởi động...";
  try{
    const r = await fetch("/api/start",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        platform:cur, api_key:$("apiKey").value.trim(), resource_id:rid,
        options:{
          interval:$("optInterval").value, keepalive_sec:$("optKeep").value,
          auto_resume:$("optResume").checked, ws_attach:$("optWs").checked,
          activity_ping:$("optPing").checked
        }})});
    const j = await r.json();
    if(!j.ok) throw new Error(j.error);
    msg.className="msg ok"; msg.textContent="Đã BẬT phiên "+j.sid;
    refresh();
  }catch(e){ msg.className="msg err"; msg.textContent="LỖI: "+e.message; }
};

async function stopSid(sid){
  await fetch("/api/stop",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sid})});
  refresh();
}
async function pickLog(sid){
  $("logSel").value = sid; renderLog(sid, window.__logs||{});
}

function esc(s){ return String(s).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])); }

function renderLog(sid, all){
  const box=$("logbox");
  const logs = all[sid]||[];
  box.innerHTML = logs.map(l=>`<div class="${l.l}">${esc(l.t)}</div>`).join("") || "<div style='color:#8b949e'>chưa có log</div>";
  box.scrollTop = box.scrollHeight;
}

async function refresh(){
  try{
    const r = await fetch("/api/status"); const j = await r.json();
    window.__logs = j.logs||{};
    $("mode").textContent = j.background ? "background (nền)" : "foreground";
    $("ver").textContent = "v" + (j.version || "?");
    $("wsmod").textContent = "websocket: " + (j.ws_ok ? "sẵn sàng" : "THIẾU thư viện websockets");
    $("banner").innerHTML = j.background
      ? "App đang chạy NỀN — bạn có thể đóng terminal/Chrome, keep-alive vẫn tiếp tục."
      : "Đang chạy ở FOREGROUND — đóng terminal sẽ tắt app. Nhấn 'Chạy nền' để sống độc lập khỏi terminal.";
    const tb=$("sessBody");
    const ss=j.sessions||[];
    if(!ss.length){ tb.innerHTML='<tr><td colspan="8" style="color:var(--mut)">chưa có phiên nào</td></tr>'; }
    else{
      tb.innerHTML = ss.map(s=>{
        const st=s.status||{};
        const cls = st.last_error ? "err" : (st.phase==="running"?"ok":"warn");
        const pill = st.last_error ? "error" : st.phase;
        return `<tr>
         <td><code>${s.sid}</code></td><td>${s.platform}</td>
         <td style="font-size:12px">${esc(s.resource_id)}</td>
         <td><span class="pill ${cls}">${esc(pill)}</span> ${esc(st.resource_state||"")}</td>
         <td style="font-size:12px">${esc(st.last_action||"")}</td>
         <td style="font-size:12px;color:var(--err)">${esc(st.last_error||"")}</td>
         <td><span class="pill ${st.ws==="attached"?"ok":"warn"}">${esc(st.ws||"off")}</span></td>
         <td><button onclick="stopSid('${s.sid}')" class="danger" style="padding:3px 10px">Dừng</button></td>
        </tr>`;
      }).join("");
    }
    const sel=$("logSel"); const keep=sel.value;
    sel.innerHTML='<option value="">— chọn phiên —</option>'+ss.map(s=>`<option value="${s.sid}">${s.sid} (${s.platform})</option>`).join("");
    if(keep){ sel.value=keep; renderLog(keep, j.logs||{}); }
    else if(ss.length){ sel.value=ss[0].sid; renderLog(ss[0].sid, j.logs||{}); }
  }catch(e){}
}
$("logSel").onchange=()=>renderLog($("logSel").value, window.__logs||{});

$("btnBg").onclick = async ()=>{
  if(!confirm("App nền sẽ giữ mọi phiên đang chạy. Nếu app hiện tại đang foreground, nó sẽ chuyển sang nền.")) return;
  try{
    const r=await fetch("/api/background",{method:"POST"}); const j=await r.json();
    alert(j.message || (j.ok?"Đã khởi chạy nền":"Lỗi"));
  }catch(e){ alert("Lỗi: "+e.message); }
};
$("btnOff").onclick = async ()=>{
  if(!confirm("TẮT app (mất mọi phiên keep-alive)?")) return;
  await fetch("/api/shutdown",{method:"POST"});
  setTimeout(()=>{ document.body.innerHTML="<h2 style='padding:40px'>App đã tắt.</h2>"; },600);
};

async function post(url, body){
  const r = await fetch(url, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body||{})});
  return r.json();
}
let optsLoaded = false;
function applyOpts(o){
  if(optsLoaded || !o) return;
  optsLoaded = true;
  if(o.interval != null) $("gInterval").value = o.interval;
  if(o.keepalive_sec != null) $("gKeep").value = o.keepalive_sec;
  $("gProxy").checked = o.proxy !== false;
  $("gWs").checked = o.ws_attach !== false;
  $("gResume").checked = o.auto_resume !== false;
  $("gPing").checked = !!o.activity_ping;
  $("gAuto").checked = o.auto_start !== false;
}
function readOpts(){
  return {interval:+$("gInterval").value||60, keepalive_sec:+$("gKeep").value||1800,
    proxy:$("gProxy").checked, ws_attach:$("gWs").checked, auto_resume:$("gResume").checked,
    activity_ping:$("gPing").checked, auto_start:$("gAuto").checked};
}
function renderStats(j){
  const names = {shardflux:"shardflux.dev", miosa:"miosa.ai", smol:"smolmachines.com"};
  let sum = j.totals ? `${j.totals.keys} key · ${j.totals.machines} máy · ${j.totals.sessions} phiên đang chạy` : "—";
  if(j.proxy){
    sum += j.proxy.enabled
      ? ` · proxy ${j.proxy.ports}: ${j.proxy.via} req qua proxy, ${j.proxy.fallback} fallback trực tiếp`
      : " · proxy tắt";
  }
  $("sumLine").textContent = sum;
  $("statsBox").innerHTML = Object.keys(names).map(p=>{
    const s = (j.stats && j.stats[p]) || {keys:0, machines:0, sessions:0, balances:[]};
    const bal = s.balances.length
      ? s.balances.map(b=>`<div style="font-size:12.5px">${esc(b.mask)}: <b style="color:${(b.exhausted||b.invalid)?"var(--err)":"var(--ok)"}">${esc(b.text)}</b></div>`).join("")
      : "<div style='color:var(--mut);font-size:12.5px'>—</div>";
    return `<div>
      <div style="font-weight:600">${names[p]}</div>
      <div style="font-size:13px;color:var(--mut)">${s.keys} key · ${s.machines} máy · <b style="color:var(--ok)">${s.sessions}</b> phiên</div>
      <div style="margin-top:6px">${bal}</div>
    </div>`;
  }).join("");
}
function renderKeys(j){
  const tb = $("keysBody");
  const ks = j.keys || [];
  window.__keysArr = ks;
  if(!ks.length){
    tb.innerHTML = '<tr><td colspan="8" style="color:var(--mut)">chưa có key nào — dán key vào ô trên</td></tr>';
    return;
  }
  tb.innerHTML = ks.map((k,i)=>{
    const cls = (k.exhausted || k.invalid) ? "err" : (k.sessions ? "ok" : "warn");
    return `<tr>
      <td><code>${esc(k.mask)}</code></td>
      <td>${esc(k.platform)}</td>
      <td>${k.machines}</td>
      <td>${k.sessions}</td>
      <td style="${(k.exhausted||k.invalid)?"color:var(--err);font-weight:600":""}">${esc(k.balance)}</td>
      <td style="font-size:12px;color:var(--mut)">${esc(k.last_check||"—")}</td>
      <td><span class="pill ${cls}">${esc(k.status)}</span>${k.error?`<div style="font-size:11px;color:var(--err)">${esc(k.error)}</div>`:""}</td>
      <td style="white-space:nowrap">
        <button class="blue" style="padding:3px 8px" onclick="keyStart(${i})">Chạy</button>
        <button style="padding:3px 8px" onclick="keyStop(${i})">Dừng</button>
        <button class="danger" style="padding:3px 8px" onclick="keyDel(${i})">Xoá</button>
      </td>
    </tr>`;
  }).join("");
}
function renderEvents(j){
  const evs = j.events || [];
  $("evBox").innerHTML = evs.length
    ? evs.map(e=>`<div class="${e.l}">[${esc(e.t)}] ${esc(e.m)}</div>`).join("")
    : "<div style='color:var(--mut)'>chưa có sự kiện</div>";
}
async function loadKeys(){
  try{
    const j = await (await fetch("/api/keys")).json();
    if(!j.ok) return;
    applyOpts(j.options);
    renderStats(j); renderKeys(j); renderEvents(j);
  }catch(e){}
}
function kAt(i){ return (window.__keysArr||[])[i] || null; }
async function keyStart(i){
  const k = kAt(i); if(!k) return;
  const msg = $("addMsg"); msg.className = "msg"; msg.textContent = "đang chạy " + k.mask + "...";
  try{
    const j = await post("/api/keys/start", {key:k.key});
    const r = (j.results||[])[0] || {};
    if(r.error){ msg.className="msg err"; msg.textContent = "LỖI: " + r.error; }
    else { msg.className="msg ok"; msg.textContent = `${k.mask}: ${r.machines} máy, ${r.started} phiên mới`; }
  }catch(e){ msg.className="msg err"; msg.textContent="LỖI: "+e.message; }
  loadKeys();
}
async function keyStop(i){
  const k = kAt(i); if(!k) return;
  await post("/api/keys/stop", {key:k.key});
  $("addMsg").className = "msg ok";
  $("addMsg").textContent = "đã dừng phiên của " + k.mask;
  loadKeys();
}
async function keyDel(i){
  const k = kAt(i); if(!k) return;
  if(!confirm(`Xoá key ${k.mask} (${k.platform})?\nSẽ dừng ${k.sessions} phiên đang chạy của key này (máy trên cloud KHÔNG bị xóa).`)) return;
  const j = await post("/api/keys/delete", {key:k.key});
  const msg = $("addMsg");
  msg.className = "msg " + (j.ok ? "ok" : "err");
  msg.textContent = j.ok ? ("đã xóa " + k.mask) : ("LỖI: " + (j.error || "unknown"));
  loadKeys();
}
$("btnAdd").onclick = async ()=>{
  const msg = $("addMsg");
  const text = $("keysIn").value.trim();
  if(!text){ msg.className="msg err"; msg.textContent="hãy dán ít nhất 1 key"; return; }
  const btn = $("btnAdd"); btn.disabled = true;
  msg.className = "msg"; msg.textContent = "đang lưu cài đặt + kiểm tra key (có thể mất vài giây)...";
  try{
    await post("/api/options", readOpts());
    const j = await post("/api/keys/add", {text});
    if(!j.ok) throw new Error(j.error || "lỗi");
    const added = j.added || [], errs = j.errors || [];
    let line = `Đã thêm ${added.length} key` + (j.duplicates ? ` · ${j.duplicates} trùng lặp` : "");
    if(added.length){
      const machines = added.reduce((a,x)=>a+(x.machines||0),0);
      const started = added.reduce((a,x)=>a+(x.started||0),0);
      line += ` · ${machines} máy · ${started} phiên mới`;
    }
    if(errs.length){
      line += "\n" + errs.map(e=>`✗ ${e.mask}${e.platform?" ("+e.platform+")":""}: ${e.error}`).join("\n");
      msg.className = "msg err";
    } else {
      msg.className = "msg ok";
    }
    msg.textContent = line;
    if(added.length) $("keysIn").value = "";
    loadKeys();
  }catch(e){ msg.className="msg err"; msg.textContent="LỖI: "+e.message; }
  btn.disabled = false;
};
$("btnBal").onclick = async ()=>{
  const msg = $("addMsg"); msg.className="msg"; msg.textContent="đang làm mới balance...";
  try{
    const j = await post("/api/keys/refresh", {});
    msg.className = "msg ok";
    msg.textContent = `đã check ${j.updated} key` + (j.removed ? ` — xóa ${j.removed} key hết balance/hết hạn` : "");
  }catch(e){ msg.className="msg err"; msg.textContent="LỖI: "+e.message; }
  loadKeys();
};
$("btnStartAll").onclick = async ()=>{
  const msg = $("addMsg"); msg.className="msg"; msg.textContent="đang chạy tất cả key...";
  try{
    const j = await post("/api/keys/start", {});
    const rs = j.results || [];
    const started = rs.reduce((a,r)=>a+(r.started||0),0);
    const errs = rs.filter(r=>r.error);
    msg.className = "msg " + (errs.length ? "err" : "ok");
    msg.textContent = `${rs.length} key · ${started} phiên mới` + (errs.length ? ` · ${errs.length} lỗi: ` + errs.map(e=>e.mask+": "+e.error).join("; ") : "");
  }catch(e){ msg.className="msg err"; msg.textContent="LỖI: "+e.message; }
  loadKeys();
};
$("btnStopAll").onclick = async ()=>{
  if(!confirm("Dừng TẤT CẢ phiên keep-alive? Key vẫn được giữ lại.")) return;
  try{
    const j = await post("/api/keys/stop", {});
    const n = (j.stopped||[]).reduce((a,s)=>a+(s.stopped||0),0);
    $("addMsg").className = "msg ok";
    $("addMsg").textContent = `đã dừng ${n} phiên`;
  }catch(e){ $("addMsg").className="msg err"; $("addMsg").textContent="LỖI: "+e.message; }
  loadKeys();
};

setTab("shardflux");
refresh();
loadKeys();
setInterval(refresh, 3000);
setInterval(loadKeys, 3000);
</script>
</body>
</html>"""


@app.get("/")
def index():
    return HTML


@app.get("/api/ping")
def ping():
    return jsonify({"ok": True, "background": IS_BACKGROUND, "version": APP_VERSION})


@app.post("/api/list")
def api_list():
    body = request.get_json(force=True)
    try:
        items = list_resources(body.get("platform", ""), body.get("api_key", ""))
        return jsonify({"ok": True, "items": items})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:500]})


@app.post("/api/start")
def api_start():
    body = request.get_json(force=True)
    platform = body.get("platform")
    if platform not in PLATFORMS:
        return jsonify({"ok": False, "error": "platform không hợp lệ"})
    if not body.get("api_key") or not body.get("resource_id"):
        return jsonify({"ok": False, "error": "thiếu api_key hoặc resource_id"})
    for s in list(SESSIONS.values()):
        if s.platform == platform and s.resource_id == body.get("resource_id") and not s.stop_evt.is_set():
            return jsonify({"ok": False, "error": f"phiên {s.sid} đã chạy cho resource này"})
    sess = PLATFORMS[platform](
        platform, body["api_key"], body["resource_id"], body.get("options") or {}
    )
    with LOCK:
        SESSIONS[sess.sid] = sess
    sess.log(f"BẬT keep-alive cho {platform} / {body['resource_id']}")
    sess.start()
    return jsonify({"ok": True, "sid": sess.sid})


@app.post("/api/stop")
def api_stop():
    body = request.get_json(force=True)
    sid = body.get("sid")
    with LOCK:
        sess = SESSIONS.pop(sid, None)
    if not sess:
        return jsonify({"ok": False, "error": "không tìm thấy phiên"})
    sess.stop()
    sess.log("ĐÃ DỪNG theo yêu cầu", "warn")
    return jsonify({"ok": True})


@app.get("/api/status")
def api_status():
    sessions = []
    logs = {}
    with LOCK:
        for s in SESSIONS.values():
            sessions.append(
                {"sid": s.sid, "platform": s.platform, "resource_id": s.resource_id, "status": dict(s.status)}
            )
            logs[s.sid] = list(s.logs)
    return jsonify({"sessions": sessions, "logs": logs, "background": IS_BACKGROUND, "ws_ok": WS_OK, "version": APP_VERSION})


@app.get("/api/keys")
def api_keys_list():
    with KEYLOCK:
        recs = [dict(k) for k in STORE["keys"]]
        opts = dict(STORE["options"])
        info_map = {k: dict(v) for k, v in KEYINFO.items()}
    sess_count = {}
    with LOCK:
        for s in SESSIONS.values():
            sess_count[s.api_key] = sess_count.get(s.api_key, 0) + 1
    keys_out = []
    stats = {p: {"keys": 0, "machines": 0, "sessions": 0, "balances": []} for p in PLATFORMS}
    for r in recs:
        k = r.get("key")
        if not k:
            continue
        pf = r.get("platform", "?")
        i = info_map.get(k, {})
        bal = i.get("balance") or {}
        n_sess = sess_count.get(k, 0)
        machines = len(i.get("machines") or [])
        if bal.get("invalid"):
            status = "key không hợp lệ"
        elif bal.get("exhausted"):
            status = "HẾT BALANCE"
        elif i.get("error"):
            status = "lỗi check"
        elif n_sess:
            status = "đang chạy"
        else:
            status = "đã lưu"
        row = {
            "key": k,
            "mask": mask_key(k),
            "platform": pf,
            "machines": machines,
            "sessions": n_sess,
            "balance": bal.get("text", "?"),
            "exhausted": bool(bal.get("exhausted")),
            "invalid": bool(bal.get("invalid")),
            "last_check": i.get("last_check") or "",
            "error": i.get("error") or "",
            "status": status,
            "added_at": r.get("added_at", ""),
        }
        keys_out.append(row)
        if pf in stats:
            st = stats[pf]
            st["keys"] += 1
            st["machines"] += machines
            st["sessions"] += n_sess
            st["balances"].append(
                {"mask": mask_key(k), "text": row["balance"], "exhausted": row["exhausted"], "invalid": row["invalid"]}
            )
    with PROXY_LOCK:
        proxy = {
            "enabled": bool(opts.get("proxy", True)),
            "ports": "2000-2199",
            "via": PROXY_STATS["via"],
            "fallback": PROXY_STATS["fallback"],
        }
    totals = {
        "keys": len(keys_out),
        "machines": sum(s["machines"] for s in stats.values()),
        "sessions": sum(sess_count.values()),
    }
    return jsonify(
        {
            "ok": True,
            "keys": keys_out,
            "stats": stats,
            "totals": totals,
            "options": opts,
            "events": list(EVENTS)[::-1],
            "proxy": proxy,
        }
    )


@app.post("/api/options")
def api_options():
    body = request.get_json(force=True) or {}
    with KEYLOCK:
        if "interval" in body:
            STORE["options"]["interval"] = clamp(body["interval"], 10, 86400, 60)
        if "keepalive_sec" in body:
            STORE["options"]["keepalive_sec"] = clamp(body["keepalive_sec"], 60, 43200, 1800)
        for b in ("auto_resume", "ws_attach", "activity_ping", "proxy", "auto_start"):
            if b in body:
                STORE["options"][b] = bool(body[b])
        save_store()
        opts = dict(STORE["options"])
    return jsonify({"ok": True, "options": opts})


@app.post("/api/keys/add")
def api_keys_add():
    body = request.get_json(force=True) or {}
    tokens = parse_key_tokens(body.get("text") or "")
    if not tokens:
        return jsonify({"ok": False, "error": "không tìm thấy key nào"})
    opts = current_options()
    added, errors, dup = [], [], 0
    for tok in tokens:
        with KEYLOCK:
            exists = any(k.get("key") == tok for k in STORE["keys"])
        if exists:
            dup += 1
            continue
        platform = detect_platform(tok)
        if not platform:
            errors.append({"mask": mask_key(tok), "error": "không nhận diện được nền tảng (cần sfk_/msk_/smk_)"})
            continue
        try:
            bal = fetch_balance(platform, tok)
        except Exception as e:
            errors.append({"mask": mask_key(tok), "error": f"kiểm tra balance lỗi: {str(e)[:200]}"})
            continue
        if bal.get("invalid"):
            errors.append({"mask": mask_key(tok), "platform": platform, "error": "key không hợp lệ (401)"})
            continue
        if bal.get("exhausted"):
            errors.append({"mask": mask_key(tok), "platform": platform, "error": "key đã HẾT BALANCE — không thêm"})
            continue
        try:
            items = list_resources(platform, tok)
        except Exception as e:
            errors.append({"mask": mask_key(tok), "platform": platform, "error": f"lấy danh sách máy lỗi: {str(e)[:200]}"})
            continue
        entry = {"key": tok, "platform": platform, "added_at": now_iso(), "enabled": True}
        with KEYLOCK:
            STORE["keys"].append(entry)
            save_store()
            info = KEYINFO.setdefault(tok, {})
            info.update(
                {"balance": bal, "machines": [i["label"] for i in items], "last_check": now_iso(), "error": ""}
            )
        started = 0
        for it in items:
            if spawn_session(platform, tok, it["id"], opts):
                started += 1
        event(f"thêm key {mask_key(tok)} ({platform}): {len(items)} máy, {started} phiên mới", "info")
        added.append(
            {"mask": mask_key(tok), "platform": platform, "machines": len(items), "started": started, "balance": bal.get("text", "")}
        )
    return jsonify({"ok": True, "added": added, "errors": errors, "duplicates": dup})


@app.post("/api/keys/start")
def api_keys_start():
    body = request.get_json(force=True) or {}
    key = (body.get("key") or "").strip()
    opts = current_options()
    with KEYLOCK:
        recs = [k.get("key") for k in STORE["keys"] if k.get("key")]
    targets = [key] if key else recs
    results = []
    for k in targets:
        r = start_key(k, opts)
        results.append({"mask": mask_key(k), **r})
    return jsonify({"ok": True, "results": results})


@app.post("/api/keys/stop")
def api_keys_stop():
    body = request.get_json(force=True) or {}
    key = (body.get("key") or "").strip()
    with KEYLOCK:
        recs = [k.get("key") for k in STORE["keys"] if k.get("key")]
    targets = [key] if key else recs
    stopped = []
    for k in targets:
        n = stop_key_sessions(k, "dừng theo yêu cầu")
        stopped.append({"mask": mask_key(k), "stopped": n})
    return jsonify({"ok": True, "stopped": stopped})


@app.post("/api/keys/delete")
def api_keys_delete():
    body = request.get_json(force=True) or {}
    key = (body.get("key") or "").strip()
    if not key:
        return jsonify({"ok": False, "error": "thiếu key"})
    removed, n = remove_key(key, "xóa theo yêu cầu")
    if not removed:
        return jsonify({"ok": False, "error": "key không có trong kho"})
    return jsonify({"ok": True, "stopped": n})


@app.post("/api/keys/refresh")
def api_keys_refresh():
    body = request.get_json(force=True) or {}
    key = (body.get("key") or "").strip()
    with KEYLOCK:
        recs = [dict(k) for k in STORE["keys"]]
    targets = [r for r in recs if not key or r.get("key") == key]
    updated = removed = 0
    for r in targets:
        k = r.get("key")
        if not k:
            continue
        bal = refresh_key_balance(k, r.get("platform"), update_machines=True)
        if bal is None:
            continue
        updated += 1
        if bal.get("invalid"):
            remove_key(k, "key không hợp lệ (401)", r.get("platform"))
            removed += 1
        elif bal.get("exhausted"):
            remove_key(k, "hết CPU-h (%.1f/%.0f)" % (bal.get("cpu_used", 0), bal.get("cpu_limit", 500)), r.get("platform"))
            removed += 1
    return jsonify({"ok": True, "updated": updated, "removed": removed})


@app.post("/api/background")
def api_background():
    if IS_BACKGROUND:
        return jsonify({"ok": True, "message": "app đã đang chạy nền rồi"})
    if not WS_OK:
        return jsonify({"ok": False, "message": "thiếu thư viện websockets: pip install websockets"})
    others = [p for p in find_keeper_pids() if p != os.getpid()]
    if others:
        return jsonify(
            {
                "ok": False,
                "message": "đang có %d instance keeper khác (PID %s). Dùng 'Tắt app nền' hoặc taskkill trước khi chạy nền."
                % (len(others), others),
            }
        )
    exe = sys.executable.replace("python.exe", "pythonw.exe")
    if not os.path.exists(exe):
        exe = sys.executable
    try:
        proc = subprocess.Popen(
            [exe, os.path.abspath(__file__), "--background", "--port", str(APP_PORT)],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200),
            close_fds=True,
        )
    except Exception as e:
        return jsonify({"ok": False, "message": f"spawn lỗi: {e}"})
    time.sleep(1.5)
    if proc.poll() is not None:
        return jsonify({"ok": False, "message": f"app nền thoát sớm (exit {proc.returncode}) - cổng có thể đang bị giữ"})

    def _exit_self():
        time.sleep(0.8)
        os._exit(0)

    threading.Thread(target=_exit_self, daemon=True).start()
    return jsonify(
        {
            "ok": True,
            "message": "Đã chuyển sang NỀN (PID %d). Cửa sổ/terminal này sẽ tự tắt — mở lại http://127.0.0.1:%d rồi bật lại phiên."
            % (proc.pid, APP_PORT),
        }
    )


@app.post("/api/shutdown")
def api_shutdown():
    with LOCK:
        for s in list(SESSIONS.values()):
            s.stop()
        SESSIONS.clear()

    def _kill_all():
        time.sleep(0.5)
        me = os.getpid()
        for pid in find_keeper_pids():
            if pid != me:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        capture_output=True,
                        timeout=5,
                    )
                except Exception:
                    pass
        os._exit(0)

    threading.Thread(target=_kill_all, daemon=True).start()
    return jsonify({"ok": True})


def main():
    global APP_PORT
    ap = argparse.ArgumentParser()
    ap.add_argument("--background", action="store_true")
    ap.add_argument("--port", type=int, default=8787)
    a = ap.parse_args()
    APP_PORT = a.port
    if not a.background:
        try:
            r = requests.get(f"http://127.0.0.1:{APP_PORT}/api/ping", timeout=1)
            if r.ok:
                j = r.json()
                print(
                    "CONG %d DA DUOC GIU BOI INSTANCE KHAC (background=%s version=%s). Thoat."
                    % (APP_PORT, j.get("background"), j.get("version"))
                )
                return
        except Exception:
            pass
    print("=" * 60)
    print(" Terminal Keeper v%s - http://127.0.0.1:%d" % (APP_VERSION, APP_PORT))
    print(" background:", a.background, "| websockets:", WS_OK)
    print("=" * 60, flush=True)
    threading.Thread(target=balance_monitor_loop, daemon=True).start()
    threading.Thread(target=autostart_loop, daemon=True).start()
    app.run(host="127.0.0.1", port=APP_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
