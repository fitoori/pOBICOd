#!/usr/bin/env python3
"""
Obico → Wire-Pod Bridge (production)
--------------------------------------------------------
• Auto-generates persistent webhook token (cached to disk)
• Prints ready-to-copy webhook URL at startup (with resolved IP)
• Privilege drop and HTTPS assumed via reverse proxy
• Parses all documented Obico events and routes them to Vector via Wire-Pod
• Supports configurable worker thread pool for parallel event handling
• Auto-calculates thread pool size if WORKER_THREADS=0 (default)
• Caps worker thread count to prevent exhausting system resources
"""

import os
import sys
import logging
import secrets
import re
import socket
from pathlib import Path
import http.server
import json
import queue
import threading
import signal
import time
from urllib.parse import quote_plus, parse_qs, urlparse

import requests
from requests.exceptions import RequestException, Timeout, HTTPError

# ─── CONFIGURATION ────────────────────────────────────────────────────────────

def env(key: str, default: str) -> str:
    return os.getenv(key, default)

LISTEN_IP       = env("LISTEN_IP", "0.0.0.0")
LISTEN_PORT     = int(env("LISTEN_PORT", "5050"))
WEBHOOK_PATH    = env("WEBHOOK_PATH", "/obico")
TOKEN_FILE      = Path(env("TOKEN_FILE", "/var/lib/obico_bridge/secret.token"))
LOG_FILE        = env("LOG_FILE", "/var/log/obico_bridge.log")
WIREPOD_URL     = env("WIREPOD_URL", "http://127.0.0.1:8080")
DEFAULT_SERIAL  = env("DEFAULT_SERIAL", "00E20123")
PRIORITY        = env("PRIORITY", "high")
REQUEST_TIMEOUT = int(env("REQUEST_TIMEOUT", "5"))
MAX_QUEUE_LEN   = int(env("MAX_QUEUE_LEN", "100"))
WORKER_THREADS  = int(env("WORKER_THREADS", "0"))
MAX_THREADS_CAP = int(env("MAX_THREADS_CAP", "32"))

# ─── LOGGING SETUP ────────────────────────────────────────────────────────────

try:
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
except Exception as e:
    print(f"ERROR: Cannot create log directory: {e}", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

# ─── TOKEN HANDLING ───────────────────────────────────────────────────────────

def valid(tok: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}\Z", tok))

def safe_write_token(tok: str):
    try:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(TOKEN_FILE), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, (tok + "\n").encode())
        os.close(fd)
        TOKEN_FILE.chmod(0o600)
    except FileExistsError:
        pass
    except Exception as e:
        logging.critical("Cannot write token file %s: %s", TOKEN_FILE, e)
        sys.exit(1)

def get_or_create_token(initial: str) -> str:
    if valid(initial):
        safe_write_token(initial)
        return initial
    try:
        cached = TOKEN_FILE.read_text().strip()
        if valid(cached):
            return cached
    except Exception:
        pass
    new_tok = secrets.token_hex(32)
    safe_write_token(new_tok)
    logging.info("Generated new persistent token saved to %s", TOKEN_FILE)
    return new_tok

SECRET_TOKEN = get_or_create_token(env("SECRET_TOKEN", ""))

# ─── GLOBAL QUEUE & SHUTDOWN ───────────────────────────────────────────────────

work_q    = queue.Queue(MAX_QUEUE_LEN)
_shutdown = threading.Event()

# ─── VECTOR API WITH RETRIES ──────────────────────────────────────────────────

def _wp_get(path: str, **params) -> None:
    query = "&".join(f"{k}={quote_plus(str(v))}" for k, v in params.items())
    url = f"{WIREPOD_URL}{path}?{query}" if query else f"{WIREPOD_URL}{path}"
    backoff = 1.0
    for attempt in range(3):
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return
        except (Timeout, HTTPError, RequestException) as e:
            logging.warning("Wire-Pod request failed (attempt %d): %s", attempt+1, e)
            if attempt == 2:
                raise
            time.sleep(backoff)
            backoff *= 2

def vector_say(text: str, serial: str = DEFAULT_SERIAL) -> None:
    try:
        _wp_get("/api-sdk/assume_behavior_control", priority=PRIORITY, serial=serial)
        _wp_get("/api-sdk/say_text", text=text, serial=serial)
    finally:
        try:
            _wp_get("/api-sdk/release_behavior_control", priority=PRIORITY, serial=serial)
        except Exception as e:
            logging.error("Release behavior control failed: %s", e)

# ─── EVENT HANDLING ────────────────────────────────────────────────────────────

def handle_obico_event(payload: dict) -> None:
    evt     = payload.get("event", {})
    etype   = evt.get("type") if isinstance(evt, dict) else evt
    printer = payload.get("printer", {}).get("name", "Printer")
    job     = payload.get("print", {}).get("filename", "unknown")
    serial  = DEFAULT_SERIAL

    messages = {
        "PrintStarted":       f"{printer} started printing {job}.",
        "PrintDone":          f"{printer} finished printing {job}.",
        "PrintCancelled":     f"{printer} cancelled printing {job}.",
        "PrintPaused":        f"{printer} is paused.",
        "PrintResumed":       f"{printer} has resumed printing.",
        "FilamentChange":     f"{printer} needs more filament.",
        "HeaterTargetReached":f"{printer} heater ready.",
        "HeaterCooledDown":   f"{printer} cooled down.",
        "PrintFailure":       (
                                f"Warning: possible spaghetti on {printer}."
                                if evt.get("is_warning", False)
                                else f"Failure detected on {printer}! Print paused."
                              ),
        "TestEvent":          "Webhook test received successfully."
    }

    msg = messages.get(etype)
    if msg:
        vector_say(msg, serial)
    else:
        logging.warning("Unhandled event type: %s", etype)

# ─── HTTP SERVER ──────────────────────────────────────────────────────────────

class BridgeHandler(http.server.BaseHTTPRequestHandler):
    def _bad(self, code: int, msg: str) -> None:
        self.send_error(code, msg)
        logging.warning("%s %s – %s", self.command, self.path, msg)

    def do_POST(self):
        if self.path.split("?")[0] != WEBHOOK_PATH:
            return self._bad(404, "Not Found")
        token = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        if token != SECRET_TOKEN:
            return self._bad(403, "Forbidden")
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return self._bad(400, "Empty Body")
        try:
            data = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return self._bad(400, "Invalid JSON")
        try:
            work_q.put_nowait(data)
        except queue.Full:
            return self._bad(503, "Server Busy")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        pass  # silence default logging

def run_http():
    server = http.server.ThreadingHTTPServer((LISTEN_IP, LISTEN_PORT), BridgeHandler)
    pub_ip = socket.gethostbyname(socket.gethostname()) or "127.0.0.1"
    url = f"http://{pub_ip}:{LISTEN_PORT}{WEBHOOK_PATH}?token={SECRET_TOKEN}"
    logging.info("Webhook URL: %s", url)
    print(f"\nWebhook URL ready to copy:\n    {url}\n")

    # start serving
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _shutdown.wait()
    server.shutdown()
    thread.join()

# ─── WORKER THREADS ───────────────────────────────────────────────────────────

def worker():
    while not _shutdown.is_set():
        try:
            payload = work_q.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            handle_obico_event(payload)
        except Exception:
            logging.exception("Error processing payload")
        finally:
            work_q.task_done()

# ─── SIGNAL HANDLING ─────────────────────────────────────────────────────────

signal.signal(signal.SIGPIPE, signal.SIG_IGN)
signal.signal(signal.SIGTERM, lambda *args: _shutdown.set())
signal.signal(signal.SIGINT,  lambda *args: _shutdown.set())

# ─── MAIN ENTRYPOINT ─────────────────────────────────────────────────────────

def main():
    # start HTTP server
    threading.Thread(target=run_http, daemon=True).start()

    # calculate worker threads
    if WORKER_THREADS > 0:
        count = WORKER_THREADS
    else:
        count = os.cpu_count() or 1
    count = min(count, MAX_THREADS_CAP)

    logging.info("Starting %d worker threads", count)
    for _ in range(count):
        try:
            threading.Thread(target=worker, daemon=True).start()
        except RuntimeError as e:
            logging.critical("Failed to start worker thread: %s", e)
            break

    # wait for shutdown
    _shutdown.wait()
    logging.info("Shutdown requested, exiting.")

if __name__ == "__main__":
    main()
