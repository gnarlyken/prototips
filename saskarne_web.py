import http.server
import socketserver
import threading
import subprocess
import json
import os
import sys
import time
import secrets
import base64
import queue
import webbrowser
import urllib.parse

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PORTS = 8765
PYTHON = sys.executable
DARBA_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Apakšprocesa vadītājs
# ---------------------------------------------------------------------------

class ProcesaVaditajs:
    def __init__(self, nosaukums):
        self.nosaukums = nosaukums
        self.proc = None
        self.lines = []
        self.lock = threading.Lock()

    def darbojas(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, args):
        if self.darbojas():
            return False
        with self.lock:
            self.lines = []
        self.proc = subprocess.Popen(
            args, cwd=DARBA_DIR,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        threading.Thread(target=self._lasitajs, daemon=True).start()
        return True

    def stop(self):
        if self.darbojas():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def _lasitajs(self):
        try:
            for rinda in iter(self.proc.stdout.readline, ""):
                with self.lock:
                    self.lines.append(rinda.rstrip("\n"))
        finally:
            try:
                self.proc.stdout.close()
            except Exception:
                pass

    def snapshot(self, since):
        with self.lock:
            return self.lines[since:], len(self.lines), self.darbojas()


bench_vaditajs = ProcesaVaditajs("bench")
tikla_vaditajs = ProcesaVaditajs("tikls")


# ---------------------------------------------------------------------------
# Mesendžera (chat) stāvoklis
# ---------------------------------------------------------------------------
#
# Architektūra:
#   1. Servera ECDH (P-256) pāris ir viens uz visu sesiju.
#   2. Telpas atslēga (room key) ir 32 baiti — tiek ģenerēta pirmoreiz, kad
#      kāds pievienojas, un izmantota visiem dalībniekiem.
#   3. Katrs klients pievienojoties iesniedz savu publisko atslēgu, serveris
#      izrēķina ECDH koplietošanas noslēpumu, atvasina KEK caur HKDF un ar
#      to iešifrē telpas atslēgu (AES-256-GCM) klientam.
#   4. Tālāk visi sūta paziņojumus, šifrētus uz telpas atslēgas (klienta pusē
#      caur Web Crypto API), serveris tikai pārsūta — neredz atklātos datus.
#

chat_lock = threading.Lock()
chat_server_priv = ec.generate_private_key(ec.SECP256R1())
chat_room_key = None  # 32 random bytes; izveido pirmo reizi pie pievienošanās
chat_clients = {}     # client_id -> {"nick", "queue", "joined_at"}
chat_history = []     # pēdējie ziņojumi — nodod jaunajiem klientiem
chat_history_max = 50
chat_next_id = 1


def chat_server_pub_jwk():
    pub = chat_server_priv.public_key()
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u(nums.x.to_bytes(32, "big")),
        "y": _b64u(nums.y.to_bytes(32, "big")),
    }


def _b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def chat_load_client_pub(jwk):
    x = int.from_bytes(_b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64u_decode(jwk["y"]), "big")
    nums = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return nums.public_key()


def chat_derive_kek(shared_secret, info=b"messenger-kek"):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def chat_encrypt_room_key_for(client_pub_jwk):
    """Atvasina KEK ar klientu un ar to iešifrē telpas atslēgu."""
    global chat_room_key
    with chat_lock:
        if chat_room_key is None:
            chat_room_key = secrets.token_bytes(32)
        rk = chat_room_key
    client_pub = chat_load_client_pub(client_pub_jwk)
    shared = chat_server_priv.exchange(ec.ECDH(), client_pub)
    kek = chat_derive_kek(shared)
    aes = AESGCM(kek)
    iv = secrets.token_bytes(12)
    ct = aes.encrypt(iv, rk, None)
    return _b64u(iv), _b64u(ct)


def chat_broadcast(event, exclude_id=None, store_history=True):
    """Iesūta event visu klientu rindās."""
    with chat_lock:
        if store_history and event.get("type") == "message":
            chat_history.append(event)
            if len(chat_history) > chat_history_max:
                del chat_history[: len(chat_history) - chat_history_max]
        for cid, info in chat_clients.items():
            if cid == exclude_id:
                continue
            try:
                info["queue"].put_nowait(event)
            except queue.Full:
                pass


def chat_users_list():
    with chat_lock:
        return [{"client_id": cid, "nick": info["nick"]}
                for cid, info in chat_clients.items()]


def chat_remove_client(client_id):
    with chat_lock:
        info = chat_clients.pop(client_id, None)
    if info:
        try:
            info["queue"].put_nowait(None)  # signal SSE thread to stop
        except queue.Full:
            pass
        chat_broadcast(
            {"type": "user_left", "client_id": client_id, "nick": info["nick"],
             "ts": time.time()},
            store_history=False,
        )


# ---------------------------------------------------------------------------
# HTTP apstrādātājs
# ---------------------------------------------------------------------------

class Apstradatajs(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def _json(self, statuss, dati):
        body = json.dumps(dati, ensure_ascii=False).encode("utf-8")
        self.send_response(statuss)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _telpis(self):
        garums = int(self.headers.get("Content-Length", 0) or 0)
        if not garums:
            return {}
        raw = self.rfile.read(garums)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def _faila_json(self, fails):
        celjs = os.path.join(DARBA_DIR, fails)
        if not os.path.exists(celjs):
            return {"error": fails + " vēl neeksistē"}
        with open(celjs, encoding="utf-8") as f:
            return {"data": json.load(f)}

    def _serve_chat_sse(self, client_id):
        """Server-Sent Events stream — pārsūta paziņojumus klientam reālā laikā."""
        with chat_lock:
            info = chat_clients.get(client_id)
        if info is None:
            self._json(404, {"error": "client_id not found"})
            return
        q = info["queue"]

        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()

            while True:
                try:
                    msg = q.get(timeout=15.0)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                if msg is None:
                    break
                payload = json.dumps(msg, ensure_ascii=False).encode("utf-8")
                self.wfile.write(b"data: " + payload + b"\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            # Klients aizvēra SSE — uzskatām par atvienošanos
            with chat_lock:
                still_present = client_id in chat_clients
            if still_present:
                chat_remove_client(client_id)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        ceļš = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if ceļš in ("/", "/index.html"):
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        log_map = {
            "/api/bench/log": bench_vaditajs,
            "/api/network/log": tikla_vaditajs,
        }
        if ceļš in log_map:
            since = int(qs.get("since", ["0"])[0])
            lines, total, running = log_map[ceļš].snapshot(since)
            self._json(200, {"lines": lines, "total": total, "running": running})
            return

        if ceļš == "/api/results/local":
            self._json(200, self._faila_json("rezultati.json"))
            return
        if ceļš == "/api/results/network":
            self._json(200, self._faila_json("tikla_rezultati.json"))
            return

        if ceļš == "/api/chat/users":
            self._json(200, {"users": chat_users_list()})
            return

        if ceļš == "/api/chat/stream":
            try:
                client_id = int(qs.get("client_id", ["0"])[0])
            except ValueError:
                self._json(400, {"error": "invalid client_id"})
                return
            self._serve_chat_sse(client_id)
            return

        self._json(404, {"error": "not found"})

    def do_POST(self):
        ceļš = urllib.parse.urlparse(self.path).path
        body = self._telpis()

        try:
            if ceļš == "/api/bench/start":
                ieslegts = bench_vaditajs.start([PYTHON, "-u", "veiktspejas_tests.py"])
                self._json(200, {"running": bench_vaditajs.darbojas(), "started": ieslegts})
                return
            if ceļš == "/api/bench/stop":
                bench_vaditajs.stop()
                self._json(200, {"running": False})
                return

            if ceļš == "/api/network/start":
                ieslegts = tikla_vaditajs.start([PYTHON, "-u", "tikla_tests.py"])
                self._json(200, {"running": tikla_vaditajs.darbojas(), "started": ieslegts})
                return
            if ceļš == "/api/network/stop":
                tikla_vaditajs.stop()
                self._json(200, {"running": False})
                return

            # ----- Mesendžeris -----
            if ceļš == "/api/chat/join":
                global chat_next_id
                nick = (body.get("nick") or "").strip()[:32]
                client_pub_jwk = body.get("public_key")
                if not nick or not client_pub_jwk:
                    self._json(400, {"error": "Nepieciešams 'nick' un 'public_key'"})
                    return
                iv_b64, enc_rk_b64 = chat_encrypt_room_key_for(client_pub_jwk)
                with chat_lock:
                    cid = chat_next_id
                    chat_next_id += 1
                    chat_clients[cid] = {
                        "nick": nick,
                        "queue": queue.Queue(maxsize=200),
                        "joined_at": time.time(),
                    }
                    history_snapshot = list(chat_history)
                # Paziņot pārējiem
                chat_broadcast(
                    {"type": "user_joined", "client_id": cid, "nick": nick,
                     "ts": time.time()},
                    exclude_id=cid, store_history=False,
                )
                self._json(200, {
                    "client_id": cid,
                    "server_public_key": chat_server_pub_jwk(),
                    "encrypted_room_key": enc_rk_b64,
                    "room_key_iv": iv_b64,
                    "users": chat_users_list(),
                    "history": history_snapshot,
                })
                return

            if ceļš == "/api/chat/send":
                cid = int(body.get("client_id", 0))
                with chat_lock:
                    info = chat_clients.get(cid)
                if info is None:
                    self._json(400, {"error": "Klients nav reģistrēts"})
                    return
                event = {
                    "type": "message",
                    "from_id": cid,
                    "from_nick": info["nick"],
                    "ciphertext": body.get("ciphertext", ""),  # base64
                    "iv": body.get("iv", ""),                  # base64
                    "algorithm": body.get("algorithm", "AES-256-GCM"),
                    "plain_size": int(body.get("plain_size", 0)),
                    "cipher_size": int(body.get("cipher_size", 0)),
                    "encrypt_us": float(body.get("encrypt_us", 0)),
                    "ts": time.time(),
                    "msg_id": body.get("msg_id", ""),
                }
                chat_broadcast(event, exclude_id=cid)
                self._json(200, {"ok": True, "ts": event["ts"]})
                return

            if ceļš == "/api/chat/leave":
                cid = int(body.get("client_id", 0))
                chat_remove_client(cid)
                self._json(200, {"ok": True})
                return

            self._json(404, {"error": "not found"})
        except Exception as e:
            self._json(400, {"error": str(e), "type": type(e).__name__})


class TrededServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

INDEX_HTML = r"""<!doctype html>
<html lang="lv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Drošas komunikācijas prototips</title>
<style>
  :root {
    --bg: #fafafa;
    --card: #ffffff;
    --border: #e5e5e5;
    --border-strong: #1a1a1a;
    --text: #111111;
    --text-muted: #6b6b6b;
    --text-faint: #9b9b9b;
    --accent: #000000;
    --accent-hover: #2a2a2a;
    --log-bg: #0d0d0d;
    --log-text: #d4d4d4;
    --log-dim: #707070;
    --hl-flash: #f0f0f0;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text);
    font-size: 14px; line-height: 1.5;
  }
  /* Header */
  header {
    background: var(--card);
    border-bottom: 1px solid var(--border);
    padding: 18px 28px; display: flex; align-items: center; gap: 18px;
  }
  header .brand { font-size: 15px; font-weight: 600; letter-spacing: 0.2px; }
  header .brand .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--accent); margin-right: 10px; vertical-align: 2px; }
  header .meta { font-size: 12px; color: var(--text-muted); font-family: ui-monospace, Menlo, monospace; }
  header .status { margin-left: auto; font-size: 12px; color: var(--text-muted); font-family: ui-monospace, Menlo, monospace; transition: color 0.3s; }
  header .status.flash { color: var(--text); }
  /* Tabs */
  nav {
    background: var(--card); border-bottom: 1px solid var(--border);
    padding: 0 20px; display: flex; gap: 2px; overflow-x: auto;
  }
  nav button {
    background: none; border: none; padding: 14px 18px;
    font-size: 13px; cursor: pointer; color: var(--text-muted);
    border-bottom: 2px solid transparent; font-family: inherit;
    white-space: nowrap; letter-spacing: 0.1px;
    transition: color 0.15s, border-color 0.15s;
  }
  nav button:hover:not(.active) { color: var(--text); }
  nav button.active { color: var(--text); border-bottom-color: var(--accent); font-weight: 600; }
  /* Main */
  main { padding: 24px 28px; max-width: 1300px; margin: 0 auto; }
  .section { display: none; animation: fade-in 0.18s ease; }
  .section.active { display: block; }
  @keyframes fade-in { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
  /* Card */
  .card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 6px; padding: 22px; margin-bottom: 16px;
    transition: border-color 0.2s;
  }
  .card.flash { animation: flash 0.6s ease; }
  @keyframes flash { 0% { background: var(--card); } 30% { background: var(--hl-flash); } 100% { background: var(--card); } }
  .card-header {
    display: flex; align-items: center; gap: 12px;
    margin-bottom: 16px; padding-bottom: 14px;
    border-bottom: 1px solid var(--border);
  }
  .card-header h2 { font-size: 15px; margin: 0; font-weight: 600; }
  .card-header .desc { color: var(--text-muted); font-size: 13px; }
  .card-header .badge { margin-left: auto; }
  /* Form elements */
  label { display: block; font-size: 11px; color: var(--text-muted);
          margin-bottom: 5px; font-weight: 500;
          text-transform: uppercase; letter-spacing: 0.5px; }
  input, select, textarea {
    width: 100%; padding: 8px 11px;
    border: 1px solid var(--border); border-radius: 4px;
    font-size: 13px; font-family: inherit; background: #fff; color: var(--text);
    transition: border-color 0.15s;
  }
  input:focus, select:focus, textarea:focus {
    outline: none; border-color: var(--border-strong);
  }
  textarea.mono, input.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 1.45; }
  textarea { resize: vertical; }
  /* Buttons */
  .btn {
    background: var(--accent); color: #fff; border: 1px solid var(--accent);
    padding: 8px 16px; border-radius: 4px; cursor: pointer;
    font-size: 13px; font-family: inherit; font-weight: 500;
    transition: background 0.12s, transform 0.05s;
    display: inline-flex; align-items: center; gap: 6px;
  }
  .btn:hover:not(:disabled) { background: var(--accent-hover); }
  .btn:active:not(:disabled) { transform: scale(0.97); }
  .btn:disabled { background: #e5e5e5; color: #aaa; border-color: #e5e5e5; cursor: not-allowed; }
  .btn.outline { background: transparent; color: var(--text); border-color: var(--border-strong); }
  .btn.outline:hover:not(:disabled) { background: var(--text); color: #fff; }
  .btn.ghost { background: transparent; color: var(--text-muted); border-color: var(--border); }
  .btn.ghost:hover:not(:disabled) { background: var(--bg); color: var(--text); border-color: var(--border-strong); }
  .btn-row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 12px 0; }
  .btn-row .spacer { flex: 1; }
  /* Layout helpers */
  .row { display: flex; gap: 14px; flex-wrap: wrap; align-items: flex-end; }
  .row > * { flex: 1; min-width: 140px; }
  .row > .narrow { flex: 0 0 auto; min-width: 0; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 800px) { .grid-2 { grid-template-columns: 1fr; } }
  /* Badge */
  .badge {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 3px 10px; border-radius: 12px;
    font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.6px;
    border: 1px solid var(--border);
  }
  .badge .pulse { width: 7px; height: 7px; border-radius: 50%; background: var(--text-faint); }
  .badge.on { border-color: var(--text); color: var(--text); }
  .badge.on .pulse { background: var(--text); animation: pulse 1.5s ease-in-out infinite; }
  .badge.off { color: var(--text-muted); }
  @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.9); } }
  /* Log panel */
  .log {
    background: var(--log-bg); color: var(--log-text);
    font-family: ui-monospace, Menlo, monospace; font-size: 12px;
    padding: 14px 16px; border-radius: 6px;
    height: 380px; overflow-y: auto;
    white-space: pre-wrap; word-break: break-all;
    border: 1px solid var(--border);
  }
  .log:empty::before { content: "— nav izvades —"; color: var(--log-dim); font-style: italic; }
  /* Info bar */
  .info {
    margin-top: 14px; padding: 10px 14px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 4px; font-size: 12px; color: var(--text-muted);
    font-family: ui-monospace, Menlo, monospace;
    transition: background 0.3s;
  }
  .info.flash { background: var(--hl-flash); }
  .info strong { color: var(--text); font-weight: 600; }
  .info .arrow { color: var(--text-faint); margin: 0 6px; }
  /* Toasts */
  #toasts {
    position: fixed; bottom: 24px; right: 24px;
    display: flex; flex-direction: column; gap: 8px;
    z-index: 1000; pointer-events: none;
  }
  .toast {
    background: var(--text); color: #fff;
    padding: 10px 16px; border-radius: 5px;
    font-size: 13px; box-shadow: 0 4px 14px rgba(0,0,0,0.15);
    animation: slide-in 0.2s ease;
    pointer-events: auto; max-width: 360px;
  }
  .toast.error { background: #fff; color: var(--text); border: 1px solid var(--text); }
  .toast.fade { animation: slide-out 0.25s ease forwards; }
  @keyframes slide-in { from { transform: translateX(20px); opacity: 0; } to { transform: none; opacity: 1; } }
  @keyframes slide-out { to { transform: translateX(20px); opacity: 0; } }
  /* Table */
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  table th {
    background: var(--bg); text-align: left; padding: 9px 12px;
    font-weight: 600; color: var(--text); border-bottom: 1.5px solid var(--text);
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
  }
  table td { padding: 7px 12px; border-bottom: 1px solid var(--border); font-family: ui-monospace, Menlo, monospace; }
  table tr:hover td { background: var(--bg); }
  table td.alg { font-weight: 600; }
  .empty { padding: 50px; text-align: center; color: var(--text-faint); font-style: italic; }
  /* Misc */
  .hint { color: var(--text-faint); font-size: 12px; margin-top: 4px; }
  .key-meta { font-family: ui-monospace, Menlo, monospace; font-size: 11px; color: var(--text-muted); margin-top: 6px; }
  /* Messenger */
  .msg-grid { display: grid; grid-template-columns: 1.4fr 1fr; gap: 16px; }
  @media (max-width: 980px) { .msg-grid { grid-template-columns: 1fr; } }
  .msg-list {
    background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
    height: 380px; overflow-y: auto; padding: 12px;
    display: flex; flex-direction: column; gap: 10px;
  }
  .msg-list:empty::before { content: "— vēl nav ziņojumu —"; color: var(--text-faint); font-style: italic; align-self: center; margin: auto; }
  .msg-item {
    border: 1px solid var(--border); background: var(--card);
    border-radius: 6px; padding: 8px 12px;
    animation: msg-in 0.18s ease;
  }
  @keyframes msg-in { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
  .msg-item.self { border-left: 2px solid var(--text); }
  .msg-item.system { background: var(--bg); border-style: dashed; color: var(--text-muted); font-style: italic; padding: 6px 12px; }
  .msg-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; font-size: 11px; color: var(--text-muted); font-family: ui-monospace, Menlo, monospace; }
  .msg-head strong { color: var(--text); font-weight: 600; }
  .msg-head .alg { padding: 1px 6px; border: 1px solid var(--border); border-radius: 3px; font-size: 10px; }
  .msg-body { font-size: 14px; word-break: break-word; }
  .msg-meta { margin-top: 5px; font-size: 11px; color: var(--text-faint); font-family: ui-monospace, Menlo, monospace; }
  .msg-stats th { font-size: 10px; padding: 6px 8px; }
  .msg-stats td { font-size: 12px; padding: 5px 8px; }
  .msg-stats td.empty { padding: 16px; text-align: center; }
  .chart-legend { display: flex; gap: 14px; margin-top: 8px; font-size: 11px; color: var(--text-muted); font-family: ui-monospace, Menlo, monospace; }
  .chart-legend .swatch { display: inline-block; width: 10px; height: 2px; vertical-align: middle; margin-right: 5px; }
  #msg-chart { width: 100%; height: 170px; display: block; }
  /* Results charts */
  .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  @media (max-width: 980px) { .charts-grid { grid-template-columns: 1fr; } }
  .chart-block { min-width: 0; }
  .chart-title { font-size: 12px; font-weight: 600; color: var(--text); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.4px; }
  #results-chart1, #results-chart2 { width: 100%; height: 280px; display: block; border: 1px solid var(--border); border-radius: 4px; background: var(--card); }
</style>
</head>
<body>

<header>
  <div class="brand"><span class="dot"></span>Drošas komunikācijas prototips</div>
  <div class="status" id="global-status">Gatavs</div>
</header>

<nav id="tabs">
  <button data-tab="messenger" class="active">Mesendžeris</button>
  <button data-tab="bench">Veiktspēja</button>
  <button data-tab="network">Tīkla tests</button>
  <button data-tab="results">Rezultāti</button>
</nav>

<main>

<!-- ============ Mesendžeris ============ -->
<section class="section active" id="tab-messenger">

  <div class="card">
    <div class="card-header">
      <h2>Mesendžeris</h2>
      <span class="desc">End-to-end šifrēta saziņa caur ECDH atslēgu apmaiņu</span>
      <span class="badge off" id="msg-badge"><span class="pulse"></span>Nav pievienots</span>
    </div>

    <div class="row">
      <div>
        <label>Lietotājvārds</label>
        <input type="text" id="msg-nick" value="alice" maxlength="32">
      </div>
      <div>
        <label>Šifrēšanas algoritms</label>
        <select id="msg-alg">
          <option value="AES-128-GCM">AES-128-GCM</option>
          <option value="AES-256-GCM" selected>AES-256-GCM</option>
        </select>
      </div>
      <div class="narrow">
        <label>&nbsp;</label>
        <button class="btn" id="msg-join" onclick="msgJoin()">Pievienoties</button>
      </div>
      <div class="narrow">
        <label>&nbsp;</label>
        <button class="btn outline" id="msg-leave" onclick="msgLeave()" disabled>Iziet</button>
      </div>
    </div>
    <p class="hint" id="msg-info">
      Web Crypto API (pārlūkprogrammās) nodrošina tikai AES-GCM. ChaCha20-Poly1305 un 3DES — pieejami lokālajos bencmarkos.
      Lai redzētu vairāku dalībnieku saziņu, atveriet vairākas šī loga kopijas (vai cilnes) ar atšķirīgiem lietotājvārdiem.
    </p>
  </div>

  <div class="msg-grid">

    <!-- Kreisā kolona: čats -->
    <div class="card msg-chat">
      <div class="card-header">
        <h2>Saziņa</h2>
        <span class="desc"><span id="msg-users-count">0</span> dalībnieki: <span id="msg-users">—</span></span>
      </div>
      <div class="msg-list" id="msg-list"></div>
      <div class="row" style="margin-top: 14px;">
        <div>
          <label>Ziņojums</label>
          <input type="text" id="msg-input" placeholder="Ievadiet ziņojumu un Enter..." disabled
                 onkeydown="if(event.key==='Enter') msgSend()">
        </div>
        <div class="narrow">
          <label>&nbsp;</label>
          <button class="btn" id="msg-send" onclick="msgSend()" disabled>Sūtīt</button>
        </div>
      </div>
    </div>

    <!-- Labā kolona: metrikas -->
    <div class="msg-side">

      <div class="card">
        <div class="card-header">
          <h2>Sesijas statistika</h2>
          <span class="desc"><span id="msg-stats-count">0</span> ziņojumi</span>
        </div>
        <table class="msg-stats" id="msg-stats">
          <thead>
            <tr><th>Algoritms</th><th>N</th><th>Vid. šifr. μs</th><th>Vid. atšifr. μs</th><th>Vid. RTT ms</th></tr>
          </thead>
          <tbody><tr><td colspan="5" class="empty">Nav datu</td></tr></tbody>
        </table>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>Latentums (pēdējie 50)</h2>
          <span class="desc">μs</span>
        </div>
        <canvas id="msg-chart" width="500" height="170"></canvas>
        <div class="chart-legend" id="msg-chart-legend"></div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>Eksperimentālais režīms</h2>
          <span class="desc">sweep pa izmēriem un algoritmiem</span>
        </div>
        <div class="row">
          <div>
            <label>Skaits katram (alg × izm)</label>
            <input type="number" id="exp-count" value="50" min="1" max="2000">
          </div>
          <div>
            <label>Algoritmi</label>
            <select id="exp-alg">
              <option value="both" selected>Abi (AES-128 + AES-256)</option>
              <option value="AES-128-GCM">tikai AES-128-GCM</option>
              <option value="AES-256-GCM">tikai AES-256-GCM</option>
            </select>
          </div>
        </div>
        <div style="margin-top: 12px;">
          <label>Izmēri (B, atdalīti ar komatu)</label>
          <input type="text" id="exp-sizes" value="64,256,1024,4096,16384" class="mono">
          <div class="hint">Pavisam ziņojumu = N(izm) × N(alg) × Skaits. Piem. 5 × 2 × 50 = 500.</div>
        </div>
        <div class="btn-row">
          <button class="btn" id="exp-start" onclick="msgExperiment()" disabled>Palaist eksperimentu</button>
          <button class="btn outline" onclick="msgExportMetrics('json')">Eksportēt JSON</button>
          <button class="btn outline" onclick="msgExportMetrics('csv')">Eksportēt CSV</button>
          <button class="btn ghost" onclick="msgClearMetrics()">Notīrīt</button>
        </div>
        <div class="hint" id="exp-progress">—</div>
      </div>

    </div>

  </div>
</section>

<!-- ============ Veiktspēja ============ -->
<section class="section" id="tab-bench">
  <div class="card">
    <div class="card-header">
      <h2>Lokāls šifrēšanas bencmarks</h2>
      <span class="desc">veiktspejas_tests.py · 64 B → 16 MB</span>
      <span class="badge off" id="bench-badge"><span class="pulse"></span>Neaktīvs</span>
    </div>
    <p class="hint">Pilns prets var aizņemt vairākas minūtes. Rezultāti tiks saglabāti rezultati.json.</p>
    <div class="btn-row">
      <button class="btn" id="bench-start" onclick="ProcCtl.bench.start()">Palaist</button>
      <button class="btn outline" id="bench-stop" onclick="ProcCtl.bench.stop()" disabled>Apturēt</button>
      <button class="btn ghost" onclick="loadResults('local')">Skatīt rezultātus →</button>
      <span class="spacer"></span>
      <button class="btn ghost" onclick="clearLog('bench')">Notīrīt</button>
    </div>
    <div class="log" id="bench-log"></div>
  </div>
</section>

<!-- ============ Tīkla tests ============ -->
<section class="section" id="tab-network">
  <div class="card">
    <div class="card-header">
      <h2>Tīkla veiktspējas tests</h2>
      <span class="desc">tikla_tests.py · round-trip latentums TCP</span>
      <span class="badge off" id="network-badge"><span class="pulse"></span>Neaktīvs</span>
    </div>
    <p class="hint">Mēra klient-serveris saziņas latentumu ar katru algoritmu. Rezultāti — tikla_rezultati.json.</p>
    <div class="btn-row">
      <button class="btn" id="network-start" onclick="ProcCtl.network.start()">Palaist</button>
      <button class="btn outline" id="network-stop" onclick="ProcCtl.network.stop()" disabled>Apturēt</button>
      <button class="btn ghost" onclick="loadResults('network')">Skatīt rezultātus →</button>
      <span class="spacer"></span>
      <button class="btn ghost" onclick="clearLog('network')">Notīrīt</button>
    </div>
    <div class="log" id="network-log"></div>
  </div>
</section>

<!-- ============ Rezultāti ============ -->
<section class="section" id="tab-results">
  <div class="card">
    <div class="card-header">
      <h2>Saglabātie rezultāti</h2>
      <span class="desc" id="results-info">—</span>
    </div>
    <div class="btn-row">
      <button class="btn outline" onclick="loadResults('local')">Lokāls (rezultati.json)</button>
      <button class="btn outline" onclick="loadResults('network')">Tīkls (tikla_rezultati.json)</button>
      <span class="spacer"></span>
      <button class="btn ghost" id="results-csv" onclick="exportResultsCSV()" disabled>Eksportēt CSV</button>
    </div>
  </div>

  <div class="card" id="results-charts-card" style="display: none;">
    <div class="card-header">
      <h2>Vizualizācija</h2>
      <span class="desc" id="results-charts-desc">—</span>
    </div>
    <div class="charts-grid">
      <div class="chart-block">
        <div class="chart-title" id="chart1-title">—</div>
        <canvas id="results-chart1" width="600" height="280"></canvas>
        <div class="chart-legend" id="chart1-legend"></div>
      </div>
      <div class="chart-block" id="chart2-block">
        <div class="chart-title" id="chart2-title">—</div>
        <canvas id="results-chart2" width="600" height="280"></canvas>
        <div class="chart-legend" id="chart2-legend"></div>
      </div>
    </div>
  </div>

  <div class="card" id="results-table-card" style="display: none;">
    <div class="card-header">
      <h2>Detalizēti dati</h2>
      <span class="desc">Vidējais ar 95% ticamības intervālu (CI = 1,96·σ/√N)</span>
    </div>
    <div id="results-container"></div>
  </div>

  <div class="card" id="results-empty">
    <div class="empty">Izvēlieties failu, lai ielādētu</div>
  </div>
</section>

</main>

<div id="toasts"></div>

<script>
"use strict";

// ============ Pamati ============
const $ = (id) => document.getElementById(id);
const setStatus = (t) => {
  const el = $("global-status");
  el.textContent = t;
  el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 700);
};

async function api(path, body) {
  const opts = body === undefined
    ? {}
    : { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) };
  const r = await fetch(path, opts);
  let d;
  try { d = await r.json(); } catch { throw new Error("Servera atbilde nav JSON"); }
  if (!r.ok) throw new Error(d.error || r.statusText);
  return d;
}

function toast(msg, kind) {
  const el = document.createElement("div");
  el.className = "toast" + (kind === "error" ? " error" : "");
  el.textContent = msg;
  $("toasts").appendChild(el);
  setTimeout(() => el.classList.add("fade"), 2400);
  setTimeout(() => el.remove(), 2700);
}
const errorToast = (e) => toast(typeof e === "string" ? e : (e.message || String(e)), "error");

function flashCard(id) {
  const el = $(id);
  if (!el) return;
  el.classList.remove("flash");
  void el.offsetWidth;
  el.classList.add("flash");
}

// Tabs
document.querySelectorAll("#tabs button").forEach(b => {
  b.addEventListener("click", () => switchTab(b.dataset.tab));
});
function switchTab(name) {
  document.querySelectorAll("#tabs button").forEach(x => x.classList.toggle("active", x.dataset.tab === name));
  document.querySelectorAll(".section").forEach(x => x.classList.toggle("active", x.id === "tab-" + name));
}

// ============ Procesu vadība — kopīgs komponents bench/network cilnēm ============
function appendLog(el, lines) {
  if (!lines.length) return;
  const shouldScroll = el.scrollTop + el.clientHeight >= el.scrollHeight - 30;
  el.textContent += lines.join("\n") + "\n";
  if (shouldScroll) el.scrollTop = el.scrollHeight;
}
function clearLog(name) {
  const map = { bench: "bench-log", network: "network-log" };
  const el = $(map[name]);
  if (el) el.textContent = "";
}

function setBadge(id, running, onText, offText) {
  const el = $(id);
  el.classList.toggle("on", running);
  el.classList.toggle("off", !running);
  el.innerHTML = "<span class='pulse'></span>" + (running ? onText : offText);
}

function makeProcessController(name, opts) {
  const state = { offset: 0, running: false };
  const elLog = $(name + "-log");
  const elBadge = $(name + "-badge");
  const btnStart = $(name + "-start");
  const btnStop = $(name + "-stop");

  async function poll() {
    try {
      const d = await api("/api/" + name + "/log?since=" + state.offset);
      state.offset = d.total;
      appendLog(elLog, d.lines);
      if (d.running !== state.running) {
        state.running = d.running;
        setBadge(name + "-badge", d.running, opts.onText, opts.offText);
        btnStart.disabled = d.running;
        btnStop.disabled = !d.running;
      }
    } catch {}
  }

  async function start() {
    try {
      const payload = opts.payload ? opts.payload() : {};
      await api("/api/" + name + "/start", payload);
      setStatus(opts.startedMsg);
    } catch (e) { errorToast(e); }
  }
  async function stop() {
    try { await api("/api/" + name + "/stop", {}); setStatus(opts.stoppedMsg); }
    catch (e) { errorToast(e); }
  }

  return { poll, start, stop };
}

const ProcCtl = {
  bench: makeProcessController("bench", {
    onText: "Darbojas", offText: "Neaktīvs",
    startedMsg: "Bencmarks palaists", stoppedMsg: "Bencmarks apturēts",
  }),
  network: makeProcessController("network", {
    onText: "Darbojas", offText: "Neaktīvs",
    startedMsg: "Tīkla tests palaists", stoppedMsg: "Tīkla tests apturēts",
  }),
};

// ============ Polling cikls ============
setInterval(() => {
  ProcCtl.bench.poll();
  ProcCtl.network.poll();
}, 400);

// ============ Rezultāti — tabulas, grafiki, CI, CSV ============
const Results = { kind: null, data: null };
const ALG_ORDER = ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "3DES-CBC"];
// Pelēkmākas nokrāsas (B/W ar smalkām atšķirībām)
const ALG_COLORS = {
  "AES-128-GCM":       "#000000",
  "AES-256-GCM":       "#444444",
  "ChaCha20-Poly1305": "#888888",
  "3DES-CBC":          "#bbbbbb",
};

function ci95(stdUs, n) {
  if (!n || n < 2 || stdUs == null) return null;
  return 1.96 * stdUs / Math.sqrt(n);
}

async function loadResults(kind) {
  switchTab("results");
  $("results-info").textContent = "Ielādē...";
  try {
    const d = await api("/api/results/" + kind);
    if (d.error) {
      $("results-info").textContent = d.error;
      $("results-empty").style.display = "";
      $("results-empty").innerHTML =
        '<div class="empty">Fails neeksistē — palaidiet attiecīgo bencmarku vispirms.</div>';
      $("results-charts-card").style.display = "none";
      $("results-table-card").style.display = "none";
      $("results-csv").disabled = true;
      Results.kind = null; Results.data = null;
      return;
    }
    Results.kind = kind; Results.data = d.data;
    $("results-csv").disabled = !d.data.length;
    renderResults();
  } catch (e) { errorToast(e); }
}

function renderResults() {
  const { kind, data } = Results;
  $("results-info").textContent =
    (kind === "local" ? "rezultati.json" : "tikla_rezultati.json") + " · " + data.length + " ieraksti";
  $("results-empty").style.display = "none";

  if (!data.length) {
    $("results-charts-card").style.display = "none";
    $("results-table-card").style.display = "block";
    $("results-container").innerHTML = '<div class="empty">Tukšs.</div>';
    return;
  }

  $("results-charts-card").style.display = "block";
  $("results-table-card").style.display = "block";
  renderResultsCharts();
  renderResultsTable();
}

const fmtSize = (b) => b < 1024 ? (b + " B") : b < 1048576 ? ((b/1024|0) + " KB") : ((b/1048576|0) + " MB");

function renderResultsTable() {
  const { kind, data } = Results;
  let html = "<table><thead><tr>", cols;

  if (kind === "local") {
    cols = ["Algoritms", "Izmērs", "Iter.",
            "Šifr. vid. ± CI μs", "Šifr. med. μs", "Šifr. Mbps",
            "Atšifr. vid. ± CI μs", "Atšifr. Mbps", "Izm. ×"];
    html += cols.map(c => "<th>" + c + "</th>").join("") + "</tr></thead><tbody>";
    html += data.map(r => {
      const ciE = ci95(r.sifresana.std_us, r.iteracijas);
      const ciD = ci95(r.atsifresana.std_us, r.iteracijas);
      return `<tr>
        <td class="alg">${r.algoritms}</td>
        <td>${r.datu_izmers}</td>
        <td>${r.iteracijas}</td>
        <td>${r.sifresana.videjais_us.toFixed(2)} ± ${ciE != null ? ciE.toFixed(2) : "—"}</td>
        <td>${r.sifresana.mediana_us.toFixed(2)}</td>
        <td>${r.sifresana.caurlaidspeja_mbps.toFixed(1)}</td>
        <td>${r.atsifresana.videjais_us.toFixed(2)} ± ${ciD != null ? ciD.toFixed(2) : "—"}</td>
        <td>${r.atsifresana.caurlaidspeja_mbps.toFixed(1)}</td>
        <td>${r.izmera_palielinajums.toFixed(3)}</td>
      </tr>`;
    }).join("");
  } else {
    cols = ["Algoritms", "Izmērs", "Iter.",
            "Vid. ± CI μs", "Med. μs", "Min μs", "Max μs",
            "p95 μs", "p99 μs", "σ μs"];
    html += cols.map(c => "<th>" + c + "</th>").join("") + "</tr></thead><tbody>";
    html += data.map(r => {
      const ci = ci95(r.std_us, r.iteracijas);
      return `<tr>
        <td class="alg">${r.algoritms}</td>
        <td>${fmtSize(r.datu_izmers_baiti)}</td>
        <td>${r.iteracijas}</td>
        <td>${r.videjais_latentums_us.toFixed(1)} ± ${ci != null ? ci.toFixed(1) : "—"}</td>
        <td>${r.mediana_us.toFixed(1)}</td>
        <td>${r.min_us.toFixed(1)}</td>
        <td>${r.max_us.toFixed(1)}</td>
        <td>${r.p95_us.toFixed(1)}</td>
        <td>${r.p99_us.toFixed(1)}</td>
        <td>${r.std_us.toFixed(1)}</td>
      </tr>`;
    }).join("");
  }
  html += "</tbody></table>";
  $("results-container").innerHTML = html;
}

// ----- Grafiki uz Rezultāti cilnes -----
function renderResultsCharts() {
  const { kind, data } = Results;

  // Pārgrupē pēc algoritma → array no {x: bytes, y: ...}
  const series = {};
  for (const r of data) {
    const alg = r.algoritms;
    if (!series[alg]) series[alg] = [];
    if (kind === "local") {
      series[alg].push({
        x: r.datu_izmers_baiti,
        throughput: r.sifresana.caurlaidspeja_mbps,
        encryptUs: r.sifresana.videjais_us,
        encryptCi: ci95(r.sifresana.std_us, r.iteracijas) || 0,
      });
    } else {
      series[alg].push({
        x: r.datu_izmers_baiti,
        latency: r.videjais_latentums_us,
        ci: ci95(r.std_us, r.iteracijas) || 0,
      });
    }
  }
  for (const a of Object.keys(series)) series[a].sort((a, b) => a.x - b.x);

  if (kind === "local") {
    $("chart1-title").textContent = "Caurlaidspēja (Mbps) pa datu izmēriem";
    $("chart2-title").textContent = "Šifrēšanas vidējais laiks (μs) ± 95% CI";
    $("chart2-block").style.display = "";
    $("results-charts-desc").textContent = "Lokālie šifrēšanas mērījumi (rezultati.json)";
    drawLineChart("results-chart1", "chart1-legend", series, "throughput", null,
                  { yLabel: "Mbps", xLog: true });
    drawLineChart("results-chart2", "chart2-legend", series, "encryptUs", "encryptCi",
                  { yLabel: "μs", xLog: true, yLog: true });
  } else {
    $("chart1-title").textContent = "Round-trip latentums (μs) ± 95% CI pa datu izmēriem";
    $("chart2-block").style.display = "none";
    $("results-charts-desc").textContent = "Tīkla mērījumi (tikla_rezultati.json)";
    drawLineChart("results-chart1", "chart1-legend", series, "latency", "ci",
                  { yLabel: "μs", xLog: true, yLog: true });
  }
}

function drawLineChart(canvasId, legendId, seriesMap, yKey, ciKey, opts) {
  const c = $(canvasId);
  const ctx = c.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const W = c.clientWidth, H = c.clientHeight || 280;
  c.width = W * dpr; c.height = H * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);

  const padL = 56, padR = 12, padT = 14, padB = 36;
  const pw = W - padL - padR, ph = H - padT - padB;

  const algs = ALG_ORDER.filter(a => seriesMap[a] && seriesMap[a].length);

  let xMin = Infinity, xMax = -Infinity, yMin = Infinity, yMax = -Infinity;
  for (const a of algs) for (const p of seriesMap[a]) {
    xMin = Math.min(xMin, p.x); xMax = Math.max(xMax, p.x);
    const v = p[yKey];
    if (v == null) continue;
    yMin = Math.min(yMin, v); yMax = Math.max(yMax, v);
  }
  if (!isFinite(xMin)) { return; }
  if (yMin === yMax) yMax = yMin + 1;
  if (opts.yLog && yMin <= 0) yMin = 0.1;

  const xScale = (x) => {
    if (opts.xLog) {
      const lx = Math.log10(x), lmin = Math.log10(xMin), lmax = Math.log10(xMax);
      return padL + (lmax === lmin ? pw / 2 : (lx - lmin) / (lmax - lmin) * pw);
    }
    return padL + (xMax === xMin ? pw / 2 : (x - xMin) / (xMax - xMin) * pw);
  };
  const yPad = (yMax - yMin) * 0.08;
  const yLo = opts.yLog ? yMin / 1.4 : yMin - yPad;
  const yHi = opts.yLog ? yMax * 1.4 : yMax + yPad;
  const yScale = (y) => {
    if (opts.yLog) {
      const ly = Math.log10(Math.max(0.001, y)),
            lmin = Math.log10(yLo), lmax = Math.log10(yHi);
      return padT + ph - (ly - lmin) / (lmax - lmin) * ph;
    }
    return padT + ph - (y - yLo) / (yHi - yLo) * ph;
  };

  // Asis
  ctx.strokeStyle = "#1a1a1a"; ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padL, padT); ctx.lineTo(padL, padT + ph); ctx.lineTo(padL + pw, padT + ph);
  ctx.stroke();

  // Y atzīmes
  ctx.fillStyle = "#6b6b6b"; ctx.font = "10px ui-monospace, Menlo";
  ctx.textAlign = "right";
  const yTicks = 5;
  for (let i = 0; i <= yTicks; i++) {
    const t = i / yTicks;
    const v = opts.yLog
      ? Math.pow(10, Math.log10(yLo) + t * (Math.log10(yHi) - Math.log10(yLo)))
      : yLo + t * (yHi - yLo);
    const y = padT + ph - t * ph;
    ctx.strokeStyle = "#f0f0f0";
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + pw, y); ctx.stroke();
    ctx.fillText(formatTick(v), padL - 6, y + 3);
  }
  ctx.fillText(opts.yLabel, padL - 6, padT - 4);

  // X atzīmes — tiešie x punkti
  const xs = Array.from(new Set(algs.flatMap(a => seriesMap[a].map(p => p.x)))).sort((a, b) => a - b);
  ctx.textAlign = "center";
  for (const x of xs) {
    const px = xScale(x);
    ctx.strokeStyle = "#e5e5e5";
    ctx.beginPath(); ctx.moveTo(px, padT); ctx.lineTo(px, padT + ph); ctx.stroke();
    ctx.fillStyle = "#6b6b6b";
    ctx.fillText(fmtSize(x), px, padT + ph + 14);
  }

  // Līnijas un punkti
  for (const alg of algs) {
    const color = ALG_COLORS[alg] || "#000";
    ctx.strokeStyle = color; ctx.fillStyle = color;
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    let started = false;
    for (const p of seriesMap[alg]) {
      const v = p[yKey]; if (v == null) continue;
      const x = xScale(p.x), y = yScale(v);
      if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
    }
    ctx.stroke();
    // Punkti
    for (const p of seriesMap[alg]) {
      const v = p[yKey]; if (v == null) continue;
      const x = xScale(p.x), y = yScale(v);
      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill();
      // Error bars
      if (ciKey && p[ciKey]) {
        const yLow = yScale(v - p[ciKey]), yHigh = yScale(v + p[ciKey]);
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(x, yLow); ctx.lineTo(x, yHigh);
        ctx.moveTo(x - 3, yLow); ctx.lineTo(x + 3, yLow);
        ctx.moveTo(x - 3, yHigh); ctx.lineTo(x + 3, yHigh);
        ctx.stroke();
        ctx.lineWidth = 1.6;
      }
    }
  }

  // Leģenda
  $(legendId).innerHTML = algs.map(a =>
    `<span><span class="swatch" style="background:${ALG_COLORS[a]||"#000"};height:6px;width:14px;border-radius:1px"></span>${a}</span>`
  ).join("");
}

function formatTick(v) {
  if (v >= 1000) return v.toFixed(0);
  if (v >= 100) return v.toFixed(0);
  if (v >= 10) return v.toFixed(1);
  if (v >= 1) return v.toFixed(2);
  return v.toFixed(3);
}

function exportResultsCSV() {
  const { kind, data } = Results;
  if (!data || !data.length) { toast("Nav datu", "error"); return; }
  let cols, rows;
  if (kind === "local") {
    cols = ["algoritms","datu_izmers","datu_izmers_baiti","iteracijas",
            "sifr_vid_us","sifr_med_us","sifr_std_us","sifr_p95_us","sifr_p99_us",
            "sifr_caurlaidspeja_mbps","sifr_ci95_us",
            "atsifr_vid_us","atsifr_std_us","atsifr_caurlaidspeja_mbps","atsifr_ci95_us",
            "izmera_palielinajums"];
    rows = data.map(r => [
      r.algoritms, r.datu_izmers, r.datu_izmers_baiti, r.iteracijas,
      r.sifresana.videjais_us, r.sifresana.mediana_us, r.sifresana.std_us,
      r.sifresana.p95_us, r.sifresana.p99_us, r.sifresana.caurlaidspeja_mbps,
      ci95(r.sifresana.std_us, r.iteracijas) || "",
      r.atsifresana.videjais_us, r.atsifresana.std_us, r.atsifresana.caurlaidspeja_mbps,
      ci95(r.atsifresana.std_us, r.iteracijas) || "",
      r.izmera_palielinajums,
    ]);
  } else {
    cols = ["algoritms","datu_izmers_baiti","iteracijas",
            "videjais_latentums_us","mediana_us","min_us","max_us",
            "p95_us","p99_us","std_us","ci95_us"];
    rows = data.map(r => [
      r.algoritms, r.datu_izmers_baiti, r.iteracijas,
      r.videjais_latentums_us, r.mediana_us, r.min_us, r.max_us,
      r.p95_us, r.p99_us, r.std_us, ci95(r.std_us, r.iteracijas) || "",
    ]);
  }
  const csv = [cols.join(","), ...rows.map(r => r.map(v =>
    typeof v === "number" ? Number(v.toFixed(4)) : v).join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = (kind === "local" ? "rezultati" : "tikla_rezultati") + "_" + Date.now() + ".csv";
  a.click();
  URL.revokeObjectURL(url);
  toast("Eksportēts CSV (" + data.length + " rindas)");
}

// ============ Mesendžeris ============
//
// Atslēgu apmaiņa:
//   1. Klients ģenerē ECDH P-256 pāri (Web Crypto)
//   2. Sūta savu publisko atslēgu serverim (/api/chat/join)
//   3. Saņem servera publisko atslēgu + iešifrētu telpas atslēgu
//   4. Atvasina KEK no shared secret caur HKDF, atšifrē telpas atslēgu
//   5. Importē telpas atslēgu kā AES-128-GCM un AES-256-GCM atslēgas
//   6. Atver SSE plūsmu ienākošajiem ziņojumiem
//
const Msg = {
  ecdhKeyPair: null,
  clientId: null,
  nick: null,
  roomKey256: null,  // CryptoKey AES-256-GCM
  roomKey128: null,  // CryptoKey AES-128-GCM
  sse: null,
  users: [],
  metrics: [],         // [{algorithm, plain_size, cipher_size, encrypt_us, decrypt_us, send_us, ts, self}]
  chart: { canvas: null, ctx: null },
};

// ----- Helpers -----
function b64uToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64u(bytes) {
  let s = ""; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function bytesToB64(bytes) {
  let s = ""; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ----- Atslēgu apmaiņa -----
async function msgPerformKeyExchange() {
  // 1. ECDH P-256 atslēgu pāris
  Msg.ecdhKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
  const pubJwk = await crypto.subtle.exportKey("jwk", Msg.ecdhKeyPair.publicKey);
  // Servera puse sagaida {kty,crv,x,y} — no JWK noņemam pārējos laukus
  const slimPub = { kty: pubJwk.kty, crv: pubJwk.crv, x: pubJwk.x, y: pubJwk.y };

  // 2. POST /api/chat/join
  const joinResp = await api("/api/chat/join", {
    nick: Msg.nick,
    public_key: slimPub,
  });

  // 3. Importēt servera publisko atslēgu
  const serverPub = await crypto.subtle.importKey(
    "jwk", joinResp.server_public_key,
    { name: "ECDH", namedCurve: "P-256" }, false, []
  );

  // 4. Shared secret + HKDF → KEK
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPub }, Msg.ecdhKeyPair.privateKey, 256
  );
  const sharedKey = await crypto.subtle.importKey(
    "raw", shared, "HKDF", false, ["deriveBits"]
  );
  const kekBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
      info: new TextEncoder().encode("messenger-kek") },
    sharedKey, 256
  );
  const kek = await crypto.subtle.importKey(
    "raw", kekBits, "AES-GCM", false, ["decrypt"]
  );

  // 5. Atšifrēt telpas atslēgu
  const iv = b64uToBytes(joinResp.room_key_iv);
  const enc = b64uToBytes(joinResp.encrypted_room_key);
  const roomKeyBytes = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, kek, enc
  );

  // 6. Importēt kā AES-128/256-GCM atslēgas
  Msg.roomKey256 = await crypto.subtle.importKey(
    "raw", roomKeyBytes, "AES-GCM", false, ["encrypt", "decrypt"]
  );
  Msg.roomKey128 = await crypto.subtle.importKey(
    "raw", new Uint8Array(roomKeyBytes).slice(0, 16),
    "AES-GCM", false, ["encrypt", "decrypt"]
  );

  Msg.clientId = joinResp.client_id;
  Msg.users = joinResp.users;

  // 7. Atskaņot vēsturi
  for (const ev of joinResp.history) {
    await msgHandleIncoming(ev, /*fromHistory*/true);
  }

  // 8. Atvērt SSE
  msgOpenStream();
}

function msgPickKey(algorithm) {
  return algorithm === "AES-128-GCM" ? Msg.roomKey128 : Msg.roomKey256;
}

async function msgEncrypt(plaintext, algorithm) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(plaintext);
  const t0 = performance.now();
  const buf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, msgPickKey(algorithm), data
  );
  const t1 = performance.now();
  const ct = new Uint8Array(buf);
  return {
    iv_b64: bytesToB64(iv),
    ciphertext_b64: bytesToB64(ct),
    encrypt_us: (t1 - t0) * 1000,
    plain_size: data.length,
    cipher_size: ct.length + iv.length,  // ietverot IV
  };
}

async function msgDecrypt(iv_b64, ciphertext_b64, algorithm) {
  const iv = b64ToBytes(iv_b64);
  const ct = b64ToBytes(ciphertext_b64);
  const t0 = performance.now();
  const buf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, msgPickKey(algorithm), ct
  );
  const t1 = performance.now();
  return {
    plaintext: new TextDecoder().decode(buf),
    decrypt_us: (t1 - t0) * 1000,
  };
}

// ----- SSE plūsma -----
function msgOpenStream() {
  if (Msg.sse) Msg.sse.close();
  Msg.sse = new EventSource("/api/chat/stream?client_id=" + Msg.clientId);
  Msg.sse.onmessage = async (e) => {
    try {
      const ev = JSON.parse(e.data);
      await msgHandleIncoming(ev, false);
    } catch (err) { console.error(err); }
  };
  Msg.sse.onerror = () => {
    if (Msg.clientId !== null) {
      // Pārtraukums — uzskatām par atvienošanos
      msgResetUI();
      toast("Saziņa pārtraukta", "error");
    }
  };
}

async function msgHandleIncoming(ev, fromHistory) {
  if (ev.type === "message") {
    let dec;
    try {
      dec = await msgDecrypt(ev.iv, ev.ciphertext, ev.algorithm);
    } catch (e) {
      msgRender({ system: true, text: "[Atšifrēšanas kļūda no " + ev.from_nick + "]" });
      return;
    }
    msgRender({
      self: false, nick: ev.from_nick, text: dec.plaintext,
      algorithm: ev.algorithm,
      plain_size: ev.plain_size, cipher_size: ev.cipher_size,
      encrypt_us: ev.encrypt_us, decrypt_us: dec.decrypt_us,
      ts: ev.ts,
    });
    if (!fromHistory) {
      Msg.metrics.push({
        algorithm: ev.algorithm, plain_size: ev.plain_size, cipher_size: ev.cipher_size,
        encrypt_us: ev.encrypt_us, decrypt_us: dec.decrypt_us,
        send_us: null, ts: ev.ts, self: false,
      });
      msgUpdateMetrics();
    }
  } else if (ev.type === "user_joined") {
    Msg.users.push({ client_id: ev.client_id, nick: ev.nick });
    msgUpdateRoster();
    msgRender({ system: true, text: ev.nick + " pievienojās" });
  } else if (ev.type === "user_left") {
    Msg.users = Msg.users.filter(u => u.client_id !== ev.client_id);
    msgUpdateRoster();
    msgRender({ system: true, text: ev.nick + " pameta sarunu" });
  }
}

// ----- UI darbības -----
async function msgJoin() {
  const nick = $("msg-nick").value.trim();
  if (!nick) { toast("Ievadiet lietotājvārdu", "error"); return; }
  if (!window.crypto || !crypto.subtle) {
    toast("Pārlūks neatbalsta Web Crypto API", "error"); return;
  }
  $("msg-join").disabled = true;
  Msg.nick = nick;
  try {
    await msgPerformKeyExchange();
    setBadge("msg-badge", true, "Pievienots · " + nick, "Nav pievienots");
    $("msg-leave").disabled = false;
    $("msg-input").disabled = false;
    $("msg-send").disabled = false;
    $("msg-nick").disabled = true;
    $("exp-start").disabled = false;
    msgUpdateRoster();
    setStatus("Mesendžeris: pievienots kā " + nick);
    msgRender({ system: true, text: "Jūs pievienojāties (" + Msg.users.length + " dalībnieki)" });
  } catch (e) {
    Msg.clientId = null; Msg.nick = null;
    $("msg-join").disabled = false;
    errorToast("Pievienošanās: " + e.message);
  }
}

async function msgLeave() {
  if (Msg.sse) { Msg.sse.close(); Msg.sse = null; }
  if (Msg.clientId !== null) {
    try { await api("/api/chat/leave", { client_id: Msg.clientId }); } catch {}
  }
  msgResetUI();
  setStatus("Mesendžeris: atvienots");
}

function msgResetUI() {
  Msg.clientId = null;
  Msg.nick = null;
  Msg.users = [];
  if (Msg.sse) { Msg.sse.close(); Msg.sse = null; }
  setBadge("msg-badge", false, "", "Nav pievienots");
  $("msg-join").disabled = false;
  $("msg-leave").disabled = true;
  $("msg-input").disabled = true;
  $("msg-send").disabled = true;
  $("msg-nick").disabled = false;
  $("exp-start").disabled = true;
  msgUpdateRoster();
}

async function msgSend() {
  if (Msg.clientId === null) return;
  const text = $("msg-input").value;
  if (!text) return;
  const algorithm = $("msg-alg").value;
  $("msg-input").value = "";
  await msgSendOne(text, algorithm, /*renderSelf*/true);
}

async function msgSendOne(text, algorithm, renderSelf) {
  let enc;
  try {
    enc = await msgEncrypt(text, algorithm);
  } catch (e) { errorToast("Šifrēšana: " + e.message); return; }

  const t0 = performance.now();
  try {
    await api("/api/chat/send", {
      client_id: Msg.clientId,
      ciphertext: enc.ciphertext_b64,
      iv: enc.iv_b64,
      algorithm,
      plain_size: enc.plain_size,
      cipher_size: enc.cipher_size,
      encrypt_us: enc.encrypt_us,
    });
  } catch (e) { errorToast("Sūtīšana: " + e.message); return; }
  const send_us = (performance.now() - t0) * 1000;

  if (renderSelf) {
    msgRender({
      self: true, nick: Msg.nick, text, algorithm,
      plain_size: enc.plain_size, cipher_size: enc.cipher_size,
      encrypt_us: enc.encrypt_us, send_us,
      ts: Date.now() / 1000,
    });
  }
  Msg.metrics.push({
    algorithm, plain_size: enc.plain_size, cipher_size: enc.cipher_size,
    encrypt_us: enc.encrypt_us, decrypt_us: null, send_us,
    ts: Date.now() / 1000, self: true,
  });
  msgUpdateMetrics();
}

// ----- Renderēšana -----
function msgRender(m) {
  const list = $("msg-list");
  const el = document.createElement("div");
  if (m.system) {
    el.className = "msg-item system";
    el.textContent = m.text;
  } else {
    el.className = "msg-item" + (m.self ? " self" : "");
    const meta = [];
    if (m.plain_size != null) meta.push(m.plain_size + " B → " + m.cipher_size + " B");
    if (m.encrypt_us != null) meta.push("šifr " + m.encrypt_us.toFixed(1) + " μs");
    if (m.decrypt_us != null) meta.push("atšifr " + m.decrypt_us.toFixed(1) + " μs");
    if (m.send_us != null) meta.push("RTT " + (m.send_us / 1000).toFixed(2) + " ms");
    el.innerHTML =
      `<div class="msg-head"><strong>${escapeHtml(m.nick)}</strong>` +
      `<span class="alg">${m.algorithm}</span>` +
      `<span>${formatTime(m.ts)}</span></div>` +
      `<div class="msg-body">${escapeHtml(m.text)}</div>` +
      (meta.length ? `<div class="msg-meta">${meta.join(" · ")}</div>` : "");
  }
  list.appendChild(el);
  list.scrollTop = list.scrollHeight;
  // Limits — turam tikai pēdējos 200 elementus DOM
  while (list.childNodes.length > 200) list.removeChild(list.firstChild);
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function formatTime(ts) {
  const d = new Date(ts * 1000);
  return d.toTimeString().slice(0, 8);
}

function msgUpdateRoster() {
  $("msg-users-count").textContent = Msg.users.length;
  $("msg-users").textContent = Msg.users.length
    ? Msg.users.map(u => u.nick).join(", ")
    : "—";
}

// ----- Metrikas un grafiks -----
function msgUpdateMetrics() {
  $("msg-stats-count").textContent = Msg.metrics.length;
  // Agregēt pēc algoritma
  const groups = {};
  for (const m of Msg.metrics) {
    if (!groups[m.algorithm]) groups[m.algorithm] = { n: 0, encS: 0, encN: 0, decS: 0, decN: 0, rttS: 0, rttN: 0 };
    const g = groups[m.algorithm];
    g.n++;
    if (m.encrypt_us != null) { g.encS += m.encrypt_us; g.encN++; }
    if (m.decrypt_us != null) { g.decS += m.decrypt_us; g.decN++; }
    if (m.send_us != null)    { g.rttS += m.send_us;    g.rttN++; }
  }
  const tbody = $("msg-stats").querySelector("tbody");
  const rows = Object.keys(groups).sort().map(alg => {
    const g = groups[alg];
    const enc = g.encN ? (g.encS / g.encN).toFixed(1) : "—";
    const dec = g.decN ? (g.decS / g.decN).toFixed(1) : "—";
    const rtt = g.rttN ? (g.rttS / g.rttN / 1000).toFixed(2) : "—";
    return `<tr><td class="alg">${alg}</td><td>${g.n}</td><td>${enc}</td><td>${dec}</td><td>${rtt}</td></tr>`;
  });
  tbody.innerHTML = rows.length ? rows.join("") : '<tr><td colspan="5" class="empty">Nav datu</td></tr>';
  msgRedrawChart();
}

function msgRedrawChart() {
  if (!Msg.chart.ctx) {
    Msg.chart.canvas = $("msg-chart");
    if (!Msg.chart.canvas) return;
    Msg.chart.ctx = Msg.chart.canvas.getContext("2d");
  }
  const c = Msg.chart.canvas, ctx = Msg.chart.ctx;
  const dpr = window.devicePixelRatio || 1;
  const W = c.clientWidth, H = c.clientHeight || 170;
  c.width = W * dpr; c.height = H * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);

  const data = Msg.metrics.slice(-50);
  if (!data.length) {
    ctx.fillStyle = "#9b9b9b"; ctx.font = "11px ui-monospace, Menlo";
    ctx.fillText("nav datu", W / 2 - 25, H / 2);
    msgUpdateLegend([]);
    return;
  }

  // Y-mērogs: maksimālais latentums no encrypt+decrypt
  let maxV = 0;
  for (const m of data) {
    if (m.encrypt_us != null) maxV = Math.max(maxV, m.encrypt_us);
    if (m.decrypt_us != null) maxV = Math.max(maxV, m.decrypt_us);
  }
  if (maxV === 0) maxV = 10;
  maxV *= 1.15;

  const padL = 42, padR = 8, padT = 8, padB = 18;
  const plotW = W - padL - padR, plotH = H - padT - padB;

  // Asis
  ctx.strokeStyle = "#e5e5e5"; ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padL, padT); ctx.lineTo(padL, H - padB); ctx.lineTo(W - padR, H - padB);
  ctx.stroke();

  // Y atzīmes
  ctx.fillStyle = "#9b9b9b"; ctx.font = "10px ui-monospace, Menlo";
  for (let i = 0; i <= 4; i++) {
    const y = padT + plotH * (1 - i / 4);
    const v = (maxV * i / 4).toFixed(0);
    ctx.fillText(v + "μs", 4, y + 3);
    ctx.strokeStyle = "#f0f0f0";
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
  }

  const colorEnc = "#000000", colorDec = "#888888";
  const xAt = (i) => padL + (data.length === 1 ? plotW / 2 : (i / (data.length - 1)) * plotW);
  const yAt = (v) => padT + plotH * (1 - v / maxV);

  // Encrypt līnija (visiem)
  ctx.strokeStyle = colorEnc; ctx.lineWidth = 1.5;
  ctx.beginPath();
  let started = false;
  data.forEach((m, i) => {
    if (m.encrypt_us == null) return;
    const x = xAt(i), y = yAt(m.encrypt_us);
    if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Encrypt punkti — formas pēc algoritma
  data.forEach((m, i) => {
    if (m.encrypt_us == null) return;
    const x = xAt(i), y = yAt(m.encrypt_us);
    ctx.fillStyle = colorEnc;
    if (m.algorithm === "AES-128-GCM") {
      ctx.beginPath(); ctx.arc(x, y, 2.5, 0, Math.PI * 2); ctx.fill();
    } else {
      ctx.fillRect(x - 2.5, y - 2.5, 5, 5);
    }
  });

  // Decrypt līnija
  ctx.strokeStyle = colorDec; ctx.lineWidth = 1.2;
  ctx.setLineDash([3, 3]);
  ctx.beginPath();
  started = false;
  data.forEach((m, i) => {
    if (m.decrypt_us == null) return;
    const x = xAt(i), y = yAt(m.decrypt_us);
    if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.setLineDash([]);

  msgUpdateLegend([
    { text: "● Šifrēšana (●AES-128, ■AES-256)", color: colorEnc },
    { text: "┄ Atšifrēšana", color: colorDec },
  ]);
}

function msgUpdateLegend(items) {
  $("msg-chart-legend").innerHTML = items.map(i =>
    `<span><span class="swatch" style="background:${i.color}"></span>${i.text}</span>`
  ).join("");
}

// ----- Eksperimentālais režīms (sweep pa izmēriem un algoritmiem) -----
async function msgExperiment() {
  if (Msg.clientId === null) { toast("Vispirms pievienojieties", "error"); return; }
  const count = Math.min(2000, Math.max(1, parseInt($("exp-count").value) || 50));
  const choice = $("exp-alg").value;
  const algs = choice === "both" ? ["AES-128-GCM", "AES-256-GCM"] : [choice];

  const sizesRaw = $("exp-sizes").value;
  const sizes = sizesRaw.split(",")
    .map(s => parseInt(s.trim()))
    .filter(n => Number.isFinite(n) && n >= 1 && n <= 200000);
  if (!sizes.length) { toast("Norādiet vismaz vienu derīgu izmēru", "error"); return; }

  $("exp-start").disabled = true;
  $("msg-send").disabled = true;
  const total = count * algs.length * sizes.length;
  let done = 0;
  msgRender({ system: true,
    text: `Eksperiments: ${algs.length} alg × ${sizes.length} izm × ${count} = ${total} ziņojumi` });

  for (const size of sizes) {
    const payload = "X".repeat(size);
    for (const alg of algs) {
      for (let i = 0; i < count; i++) {
        await msgSendOne(payload, alg, /*renderSelf*/false);
        done++;
        if (done % 10 === 0 || done === total) {
          $("exp-progress").textContent =
            `${done} / ${total}  ·  šobrīd: ${alg} @ ${size} B`;
          await new Promise(r => setTimeout(r, 0));
        }
      }
    }
  }
  $("exp-progress").textContent = "Pabeigts: " + total + " ziņojumi";
  msgRender({ system: true,
    text: "Eksperiments pabeigts. Eksportējiet metrikas (JSON vai CSV), lai analizētu." });
  $("exp-start").disabled = false;
  $("msg-send").disabled = false;
}

function msgExportMetrics(format) {
  if (!Msg.metrics.length) { toast("Nav metriku ko eksportēt", "error"); return; }
  let blob, fname;
  if (format === "csv") {
    const cols = ["ts", "self", "algorithm", "plain_size", "cipher_size",
                  "encrypt_us", "decrypt_us", "send_us"];
    const lines = [cols.join(",")];
    for (const m of Msg.metrics) {
      lines.push(cols.map(c => m[c] == null ? "" : m[c]).join(","));
    }
    blob = new Blob([lines.join("\n")], { type: "text/csv" });
    fname = "messenger_metrics_" + Date.now() + ".csv";
  } else {
    const data = { nick: Msg.nick, exported_at: new Date().toISOString(), metrics: Msg.metrics };
    blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    fname = "messenger_metrics_" + Date.now() + ".json";
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = fname;
  a.click();
  URL.revokeObjectURL(url);
  toast("Eksportēts " + Msg.metrics.length + " ierakstu (" + (format || "json") + ")");
}

function msgClearMetrics() {
  Msg.metrics = [];
  msgUpdateMetrics();
  $("exp-progress").textContent = "—";
}

// Aizverot logu — paziņot serverim
window.addEventListener("beforeunload", () => {
  if (Msg.clientId !== null) {
    navigator.sendBeacon &&
      navigator.sendBeacon("/api/chat/leave",
        new Blob([JSON.stringify({ client_id: Msg.clientId })], { type: "application/json" }));
  }
});

// ============ Inicializācija ============
msgUpdateMetrics();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Iedarbina
# ---------------------------------------------------------------------------

def main():
    global PORTS
    srv = None
    for p in range(PORTS, PORTS + 10):
        try:
            srv = TrededServer(("127.0.0.1", p), Apstradatajs)
            PORTS = p
            break
        except OSError:
            continue
    if srv is None:
        print("Nevar atrast brīvu portu", file=sys.stderr)
        sys.exit(1)

    url = "http://127.0.0.1:" + str(PORTS) + "/"
    print("[SASKARNE] Klausās uz " + url)
    print("[SASKARNE] Python: " + PYTHON)
    print("[SASKARNE] Darba katalogs: " + DARBA_DIR)
    print("[SASKARNE] Pārtraukt: Ctrl+C")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[SASKARNE] Apturam...")
    finally:
        bench_vaditajs.stop()
        tikla_vaditajs.stop()
        srv.server_close()
        print("[SASKARNE] Apturēts")


if __name__ == "__main__":
    main()
