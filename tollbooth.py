#!/usr/bin/env python3
"""
Tollbooth - a mini Burp-Suite-style toolkit for learning manual web testing.

Proxy (intercept requests/responses, history) | Repeater | Intruder |
Decoder | Comparer | Target (site map) | Scope + match/replace rules

Pure standard library. Use only against systems you own or may legally test.
"""

import argparse
import base64
import difflib
import gzip
import hashlib
import html
import json
import os
import re
import select
import socket
import socketserver
import ssl
import sys
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit

__version__ = "0.2.0"

HOP_BY_HOP = {"proxy-connection", "connection", "keep-alive", "proxy-authorization"}
MAX_INTRUDER_REQUESTS = 2000


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Flow:
    id: int
    method: str
    url: str
    headers: list  # [(name, value)]
    body: bytes = b""
    note: str = ""
    ts: float = field(default_factory=time.time)
    elapsed: float = 0.0
    status: str = ""
    resp_headers: list = field(default_factory=list)
    resp_body: bytes = b""
    resp_raw: bytes = b""

    @property
    def host(self):
        return urlsplit(self.url).hostname or ""

    @property
    def port(self):
        u = urlsplit(self.url)
        return u.port or (443 if u.scheme == "https" else 80)

    @property
    def path(self):
        u = urlsplit(self.url)
        return (u.path or "/") + (f"?{u.query}" if u.query else "")

    def summary(self):
        try:
            code = self.status.split(" ")[1]
        except IndexError:
            code = ""
        return {
            "id": self.id, "method": self.method, "host": self.host, "path": self.path,
            "status": code, "length": len(self.resp_body), "ms": round(self.elapsed * 1000),
            "note": self.note,
        }


@dataclass
class Held:
    flow: Flow
    stage: str  # "request" | "response"
    orig: str
    text: str
    event: threading.Event = field(default_factory=threading.Event)
    action: str = ""  # "forward" | "drop"


class State:
    def __init__(self, scope):
        self.scope = list(scope)
        self.flows = {}
        self.pending = {}
        self.icpt_req = False
        self.icpt_resp = False
        self.rules = []  # {"target","match","replace","regex","enabled"}
        self._n = 0
        self.lock = threading.Lock()

    def new_id(self):
        with self.lock:
            self._n += 1
            return self._n

    def in_scope(self, host):
        return "*" in self.scope or host in self.scope


STATE = State(["127.0.0.1", "localhost"])


# --------------------------------------------------------------------------- #
# HTTP parsing / building
# --------------------------------------------------------------------------- #
def read_head(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 1_000_000:
            raise ValueError("headers too large")
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def parse_headers(lines):
    out = []
    for line in lines:
        if b":" in line:
            k, v = line.split(b":", 1)
            out.append((k.decode("latin1").strip(), v.decode("latin1").strip()))
    return out


def header(headers, name, default=None):
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return default


def dechunk(data):
    out, i = b"", 0
    while True:
        j = data.find(b"\r\n", i)
        if j < 0:
            return out
        try:
            size = int(data[i:j].split(b";")[0], 16)
        except ValueError:
            return out
        if size == 0:
            return out
        out += data[j + 2: j + 2 + size]
        i = j + 2 + size + 2


def parse_response(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin1") if lines and lines[0] else ""
    headers = parse_headers(lines[1:])
    if "chunked" in (header(headers, "transfer-encoding", "") or "").lower():
        body = dechunk(body)
    enc = (header(headers, "content-encoding", "") or "").lower()
    try:
        if enc == "gzip":
            body = gzip.decompress(body)
        elif enc == "deflate":
            body = zlib.decompress(body)
    except Exception:
        pass
    return status, headers, body


def record_response(flow, raw):
    flow.resp_raw = raw
    if raw:
        flow.status, flow.resp_headers, flow.resp_body = parse_response(raw)


def build_request_bytes(flow):
    lines = [f"{flow.method} {flow.path} HTTP/1.1"]
    has_host = False
    for k, v in flow.headers:
        kl = k.lower()
        if kl in HOP_BY_HOP or kl == "content-length":
            continue
        has_host |= kl == "host"
        lines.append(f"{k}: {v}")
    if not has_host:
        lines.append(f"Host: {urlsplit(flow.url).netloc}")
    if flow.body or flow.method in ("POST", "PUT", "PATCH"):
        lines.append(f"Content-Length: {len(flow.body)}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1", "replace") + flow.body


def build_response_bytes(text):
    """Turn edited response text back into wire bytes (body is sent decoded)."""
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    skip = {"content-length", "transfer-encoding", "content-encoding", "connection"}
    hdrs = [(k.strip(), v.strip()) for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)
            if k.strip().lower() not in skip]
    b = body.encode("utf-8")
    out = lines[0] + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs)
    out += f"Content-Length: {len(b)}\r\nConnection: close\r\n\r\n"
    return out.encode("latin1", "replace") + b


def send_upstream(flow):
    """Send a flow to its target (HTTP or HTTPS, cert not verified: lab tool)."""
    s = socket.create_connection((flow.host, flow.port), timeout=15)
    if urlsplit(flow.url).scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=flow.host)
    data = b""
    with s:
        s.sendall(build_request_bytes(flow))
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, ssl.SSLError):
            pass
    return data


# --------------------------------------------------------------------------- #
# Raw text <-> Flow
# --------------------------------------------------------------------------- #
def req_text(flow):
    head = f"{flow.method} {flow.url} HTTP/1.1\n"
    head += "".join(f"{k}: {v}\n" for k, v in flow.headers if k.lower() not in HOP_BY_HOP)
    return head + "\n" + flow.body.decode("utf-8", "replace")


def resp_text(flow):
    if not flow.status:
        return ""
    head = flow.status + "\n" + "".join(f"{k}: {v}\n" for k, v in flow.resp_headers)
    return head + "\n" + flow.resp_body.decode("utf-8", "replace")


def apply_text(flow, text):
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    method, url, _ = (lines[0].strip().split(" ", 2) + ["", ""])[:3]
    flow.method, flow.url = method.upper(), url
    flow.headers = [(k.strip(), v.strip())
                    for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)]
    flow.body = body.encode("utf-8")


def apply_rules(kind, text, rules):
    for r in rules:
        if not r.get("enabled", True) or r.get("target") != kind or not r.get("match"):
            continue
        try:
            if r.get("regex"):
                text = re.sub(r["match"], r.get("replace", ""), text)
            else:
                text = text.replace(r["match"], r.get("replace", ""))
        except re.error:
            pass
    return text


# --------------------------------------------------------------------------- #
# Repeater / Intruder / Decoder / Comparer
# --------------------------------------------------------------------------- #
def repeater_send(text):
    f = Flow(0, "GET", "", [])
    apply_text(f, text)
    if not f.url.startswith(("http://", "https://")):
        raise ValueError("First line must be: METHOD http(s)://host/path HTTP/1.1")
    if not STATE.in_scope(f.host):
        raise ValueError(f"{f.host} is out of scope (Options tab)")
    t0 = time.time()
    record_response(f, send_upstream(f))
    f.elapsed = time.time() - t0
    return {"status": f.status, "resp_text": resp_text(f),
            "length": len(f.resp_body), "ms": round(f.elapsed * 1000)}


def intruder_jobs(text, payloads, mode):
    parts = text.split("§")
    if len(parts) < 3 or len(parts) % 2 == 0:
        raise ValueError("Mark positions with §...§ (an even number of § signs)")
    n = len(parts) // 2
    defaults = [parts[i] for i in range(1, len(parts), 2)]

    def build(vals):
        out = parts[0]
        for i, v in enumerate(vals):
            out += v + parts[2 * i + 2]
        return out

    jobs = []
    if mode == "ram":  # battering ram: same payload in every position
        jobs = [(0, p, build([p] * n)) for p in payloads]
    else:  # sniper: one position at a time
        for pos in range(n):
            for p in payloads:
                vals = [p if i == pos else defaults[i] for i in range(n)]
                jobs.append((pos + 1, p, build(vals)))
    if len(jobs) > MAX_INTRUDER_REQUESTS:
        raise ValueError(f"Too many requests ({len(jobs)}); limit is {MAX_INTRUDER_REQUESTS}")
    return jobs


def intruder_run(text, payloads, mode="sniper"):
    jobs = intruder_jobs(text, payloads, mode)

    def one(item):
        n, (pos, payload, req) = item
        res = {"n": n + 1, "position": pos, "payload": payload,
               "status": "", "length": 0, "ms": 0, "error": ""}
        try:
            f = Flow(0, "GET", "", [])
            apply_text(f, req)
            if not STATE.in_scope(f.host):
                raise ValueError("out of scope")
            t0 = time.time()
            record_response(f, send_upstream(f))
            res["ms"] = round((time.time() - t0) * 1000)
            res["status"] = f.status.split(" ")[1] if " " in f.status else ""
            res["length"] = len(f.resp_body)
        except Exception as e:
            res["error"] = str(e)
        return res

    with ThreadPoolExecutor(max_workers=5) as ex:
        return list(ex.map(one, enumerate(jobs)))


DECODERS = {
    "b64enc": lambda s: base64.b64encode(s.encode()).decode(),
    "b64dec": lambda s: base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace"),
    "urlenc": lambda s: quote(s, safe=""),
    "urldec": lambda s: unquote(s),
    "hexenc": lambda s: s.encode().hex(),
    "hexdec": lambda s: bytes.fromhex(s.replace(" ", "")).decode("utf-8", "replace"),
    "htmlenc": lambda s: html.escape(s),
    "htmldec": lambda s: html.unescape(s),
    "md5": lambda s: hashlib.md5(s.encode()).hexdigest(),
    "sha1": lambda s: hashlib.sha1(s.encode()).hexdigest(),
    "sha256": lambda s: hashlib.sha256(s.encode()).hexdigest(),
}


def compare(a, b):
    return [[line[:2].strip() or " ", line[2:]]
            for line in difflib.ndiff(a.splitlines(), b.splitlines()) if not line.startswith("? ")]


# --------------------------------------------------------------------------- #
# Proxy
# --------------------------------------------------------------------------- #
def respond(sock, code, text):
    body = text.encode()
    sock.sendall(f"HTTP/1.1 {code} {text}\r\nContent-Length: {len(body)}\r\n"
                 f"Connection: close\r\n\r\n".encode() + body)


def hold(flow, stage, text):
    h = Held(flow, stage, text, text)
    STATE.pending[flow.id] = h
    h.event.wait(timeout=600)
    STATE.pending.pop(flow.id, None)
    return h


def tunnel(a, b):
    socks = [a, b]
    while True:
        r, _, _ = select.select(socks, [], [], 30)
        if not r:
            return
        for s in r:
            data = s.recv(65536)
            if not data:
                return
            (b if s is a else a).sendall(data)


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(30)
        try:
            head, rest = read_head(sock)
            lines = head.split(b"\r\n")
            method, target, _ = lines[0].decode("latin1").split(" ", 2)
            headers = parse_headers(lines[1:])
            if method == "CONNECT":
                return self.connect(sock, target)

            body = rest
            want = int(header(headers, "content-length", "0") or 0)
            while len(body) < want:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                body += chunk
            if not target.startswith("http"):
                return respond(sock, 400, "Tollbooth expects proxy-style absolute URLs")

            flow = Flow(STATE.new_id(), method, target, headers, body)
            STATE.flows[flow.id] = flow
            if not STATE.in_scope(flow.host):
                flow.note = "OUT OF SCOPE"
                return respond(sock, 403, "Blocked by Tollbooth scope")

            apply_text(flow, apply_rules("request", req_text(flow), STATE.rules))
            if STATE.icpt_req:
                h = hold(flow, "request", req_text(flow))
                if h.action != "forward":
                    flow.note = "DROPPED"
                    return respond(sock, 403, "Dropped by Tollbooth")
                if h.text != h.orig:
                    apply_text(flow, h.text)
                    flow.note = "EDITED"

            t0 = time.time()
            raw = send_upstream(flow)
            flow.elapsed = time.time() - t0
            record_response(flow, raw)
            if not raw:
                return respond(sock, 502, "No response from upstream")

            original = resp_text(flow)
            text = apply_rules("response", original, STATE.rules)
            if STATE.icpt_resp:
                h = hold(flow, "response", text)
                if h.action != "forward":
                    flow.note = (flow.note + " RESP DROPPED").strip()
                    return respond(sock, 403, "Response dropped by Tollbooth")
                text = h.text
            if text != original:
                raw = build_response_bytes(text)
                record_response(flow, raw)
                flow.note = (flow.note + " RESP MODIFIED").strip()
            sock.sendall(raw)
        except Exception as e:
            try:
                respond(sock, 502, f"Tollbooth error: {e}")
            except Exception:
                pass

    def connect(self, sock, target):
        host, _, port = target.partition(":")
        flow = Flow(STATE.new_id(), "CONNECT", f"https://{target}", [],
                    note="TLS tunnel (not decrypted)")
        STATE.flows[flow.id] = flow
        if not STATE.in_scope(host):
            flow.note = "OUT OF SCOPE"
            return respond(sock, 403, "Blocked by Tollbooth scope")
        with socket.create_connection((host, int(port or 443)), timeout=15) as up:
            sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            tunnel(sock, up)


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# --------------------------------------------------------------------------- #
# Web UI + JSON API
# --------------------------------------------------------------------------- #
UI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.html")


class UIHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200, ctype="application/json", extra=None):
        data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _guard(self):
        """Block DNS-rebinding (Host check) before serving anything."""
        if self.headers.get("Host", "").split(":")[0] not in ("127.0.0.1", "localhost"):
            self._send({"error": "forbidden"}, 403)
            return False
        return True

    def do_GET(self):
        if not self._guard():
            return
        path = urlsplit(self.path).path
        if path == "/":
            with open(UI_PATH, "rb") as f:
                return self._send(f.read(), ctype="text/html; charset=utf-8")
        if path == "/api/state":
            return self._send({
                "intercept": {"request": STATE.icpt_req, "response": STATE.icpt_resp},
                "flows": [f.summary() for f in list(STATE.flows.values())[-3000:]],
                "pending": [{"id": h.flow.id, "stage": h.stage, "text": h.text}
                            for h in list(STATE.pending.values())],
            })
        if path.startswith("/api/flow/"):
            f = STATE.flows.get(int(path.rsplit("/", 1)[1]))
            if not f:
                return self._send({"error": "not found"}, 404)
            return self._send({"req_text": req_text(f), "resp_text": resp_text(f)})
        if path == "/api/scope":
            return self._send({"scope": STATE.scope})
        if path == "/api/rules":
            return self._send({"rules": STATE.rules})
        if path == "/api/export":
            data = [{**f.summary(), "request": req_text(f), "response": resp_text(f)}
                    for f in STATE.flows.values()]
            return self._send(json.dumps(data, indent=2).encode(),
                              extra={"Content-Disposition": "attachment; filename=history.json"})
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        # Custom header forces a CORS preflight, which we never grant -> blocks CSRF.
        if not self._guard():
            return
        if self.headers.get("X-Tollbooth") != "1":
            return self._send({"error": "missing X-Tollbooth header"}, 403)
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            self._send(self.route(urlsplit(self.path).path, body))
        except Exception as e:
            self._send({"error": str(e)}, 400)

    def route(self, path, b):
        if path == "/api/intercept":
            STATE.icpt_req = bool(b.get("request"))
            STATE.icpt_resp = bool(b.get("response"))
            if not (STATE.icpt_req or STATE.icpt_resp):
                for h in list(STATE.pending.values()):
                    h.action = "forward"
                    h.event.set()
            return {"ok": True}
        if path in ("/api/forward", "/api/drop"):
            h = STATE.pending.pop(int(b["id"]), None)
            if not h:
                return {"error": "no such held item"}
            h.action = "forward" if path == "/api/forward" else "drop"
            if b.get("text") is not None:
                h.text = b["text"]
            h.event.set()
            return {"ok": True}
        if path == "/api/send":
            return repeater_send(b["text"])
        if path == "/api/intruder":
            payloads = [p for p in b.get("payloads", "").split("\n") if p != ""]
            return {"results": intruder_run(b["text"], payloads, b.get("mode", "sniper"))}
        if path == "/api/decode":
            try:
                return {"result": DECODERS[b["op"]](b.get("data", ""))}
            except Exception as e:
                return {"error": f"{type(e).__name__}: {e}"}
        if path == "/api/compare":
            return {"diff": compare(b.get("a", ""), b.get("b", ""))}
        if path == "/api/scope":
            STATE.scope = [s.strip() for s in b.get("scope", []) if s.strip()]
            return {"scope": STATE.scope}
        if path == "/api/rules":
            STATE.rules = b.get("rules", [])
            return {"rules": STATE.rules}
        if path == "/api/clear":
            STATE.flows.clear()
            return {"ok": True}
        return {"error": "unknown endpoint"}


# --------------------------------------------------------------------------- #
def main():
    global STATE
    ap = argparse.ArgumentParser(description="Tollbooth - mini Burp-style toolkit")
    ap.add_argument("--proxy-port", type=int, default=8080)
    ap.add_argument("--ui-port", type=int, default=8081)
    ap.add_argument("--scope", nargs="+", default=["127.0.0.1", "localhost"],
                    help="hosts that may be contacted ('*' = anything; lab use only)")
    args = ap.parse_args()

    STATE = State(args.scope)
    proxy = ProxyServer(("127.0.0.1", args.proxy_port), ProxyHandler)
    ui = ThreadingHTTPServer(("127.0.0.1", args.ui_port), UIHandler)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    print(f"Tollbooth {__version__}\n  Proxy : 127.0.0.1:{args.proxy_port}  (set this in your browser)"
          f"\n  UI    : http://127.0.0.1:{args.ui_port}\n  Scope : {', '.join(STATE.scope)}")
    try:
        ui.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    sys.exit(main())
