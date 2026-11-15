from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from purest.config import get_config
from purest.http_threads import NamedThreadingMixIn
from purest.websocket import WebSocket, is_websocket_upgrade

endpoints: dict = {}
ws_endpoints: dict = {}
_ws_listen_port: int | None = None


def register_endpoints(modules) -> int:
    """Register endpoint modules. Returns count of registered method handlers."""
    global endpoints, ws_endpoints
    cfg = get_config()
    logger = cfg.logger
    logger.info("Registering API endpoints")
    endpoints = {}
    ws_endpoints = {}
    registered = 0
    for endpoint_module in modules:
        try:
            for amethod in ["GET", "POST"]:
                if amethod not in endpoints:
                    endpoints[amethod] = {}
                if amethod not in ws_endpoints:
                    ws_endpoints[amethod] = {}

                try:
                    impl = getattr(endpoint_module, f"impl_{amethod}")
                except AttributeError:
                    continue

                is_ws = getattr(impl, "_purest_websocket", False)
                dest = ws_endpoints if is_ws else endpoints
                kind = "WS" if is_ws else amethod
                logger.debug(f"Registering: {kind} - {endpoint_module.ENDP_PATH}")

                if endpoint_module.ENDP_PATH not in dest[amethod]:
                    dest[amethod][endpoint_module.ENDP_PATH] = impl
                    registered += 1
                else:
                    logger.error(
                        f"Could not register {amethod} endpoint from module {endpoint_module.__name__}: "
                        "endpoint path already taken."
                    )
                    os._exit(0)
        except Exception as e:
            logger.error(f"Could not register an endpoint: {endpoint_module.__name__}")
            logger.exception(e)
            os._exit(0)
    logger.info(f"Registered {registered} endpoints.")
    return registered


class ThreadingWSServer(NamedThreadingMixIn, HTTPServer):
    daemon_threads = True
    thread_prefix = "WS#"


class APIServer(BaseHTTPRequestHandler):
    @staticmethod
    def log_message(*args):
        pass

    def __init__(self, request, client_address, server):
        self.server_version = get_config().server_version
        self.sys_version = ""
        super().__init__(request, client_address, server)

    def error(self, code, message):
        self.send_response(code)
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode("utf-8"))
        self.wfile.flush()

    def _send_cors_headers(self):
        origin = self.headers.get("Origin") or "*"
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
        self.send_header("Access-Control-Max-Age", "1728000")
        if origin != "*":
            self.send_header("Vary", "Origin")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _write_endpoint_result(self, path, endpoint_exec_result):
        cfg = get_config()
        logger = cfg.logger
        self.send_response(endpoint_exec_result["rc"])
        content_type = endpoint_exec_result.get("content-type", "application/json")
        self.send_header("Content-type", content_type)
        if endpoint_exec_result.get("cache-control"):
            self.send_header("Cache-Control", endpoint_exec_result["cache-control"])
        extra_headers = endpoint_exec_result.get("headers") or {}
        for header, value in extra_headers.items():
            self.send_header(header, value)
        if extra_headers:
            self.send_header("Access-Control-Expose-Headers", ", ".join(extra_headers))
        self._send_cors_headers()
        self.end_headers()
        data = endpoint_exec_result["data"]
        binary = isinstance(data, (bytes, bytearray))
        if binary:
            body = bytes(data)
        elif isinstance(data, dict):
            body = json.dumps(data).encode("utf-8")
        else:
            body = str(data).encode("utf-8")
        self.wfile.write(body)
        self.wfile.flush()
        real_ip = self.headers.get("X-Real-IP") or self.client_address[0]
        size = len(body)
        quiet = path in cfg.debug_quiet_paths and int(endpoint_exec_result["rc"]) == 200
        log = logger.debug if quiet else logger.info
        log(f"[{real_ip}] - RQ: {self.command} {self.path}: {endpoint_exec_result['rc']}. Data: TX:{size}b")
        logger.debug(f"RQ Headers: {self.headers}")
        if binary:
            logger.debug("Data omitted: binary.")
        elif size < 8192:
            logger.debug(f"Data: {body.decode('utf-8', errors='replace')}")
        else:
            logger.debug("Data omitted: too big.")

    def do_GET(self):
        cfg = get_config()
        logger = cfg.logger
        try:
            ip_from_headers = self.headers.get("X-Real-IP")
            if ip_from_headers is not None:
                self.client_address = (ip_from_headers, self.client_address[1])
            parsed = urlsplit(self.path)
            path = parsed.path
            if path in ws_endpoints.get("GET", {}):
                port_hint = _ws_listen_port if _ws_listen_port is not None else "?"
                self.error(426, f"This endpoint is a WebSocket. Connect to port {port_hint}.")
                logger.info(f"[{self.client_address[0]}] - RQ: GET {path}: 426")
                return
            if path in endpoints.get("GET", {}):
                query = {
                    key: values[0] if len(values) == 1 else values
                    for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
                }
                fn = endpoints["GET"][path]
                if query:
                    endpoint_exec_result = fn(self.headers, query)
                else:
                    endpoint_exec_result = fn(self.headers)
                self._write_endpoint_result(path, endpoint_exec_result)
            else:
                self.error(404, f"No such endpoint: '{path}'")
                logger.info(f"RQ: GET {self.path}: 404")
        except Exception as e:
            try:
                self.error(500, f"Server error: {e.__class__.__name__}")
            except Exception:
                pass
            logger.error(f"RQ: GET {self.path}: 500 ({e.__class__.__name__})")
            logger.exception(e)

    def do_POST(self):
        cfg = get_config()
        logger = cfg.logger
        try:
            ip_from_headers = self.headers.get("X-Real-IP")
            if ip_from_headers is not None:
                self.client_address = (ip_from_headers, self.client_address[1])
            if self.path in endpoints.get("POST", {}):
                data_length = int(self.headers.get("Content-Length"))
                if data_length > cfg.max_data_len_bytes:
                    self.send_response(413)
                    self._send_cors_headers()
                    self.end_headers()
                    return
                try:
                    data = json.loads(self.rfile.read(data_length).decode("utf-8"))
                except Exception:
                    self.error(400, "Malformed data")
                    return
                endpoint_exec_result = endpoints["POST"][self.path](self.headers, data)
                self._write_endpoint_result(self.path, endpoint_exec_result)
            else:
                self.error(404, f"No such endpoint: '{self.path}'")
                logger.info(f"RQ: POST {self.path}: 404")
        except Exception as e:
            try:
                self.error(500, f"Server error: {e.__class__.__name__}")
            except Exception:
                pass
            logger.error(f"RQ: POST {self.path}: 500 ({e.__class__.__name__})")
            logger.exception(e)


class WSServer(APIServer):
    def do_POST(self):
        self.error(405, "WebSocket port accepts GET upgrades only.")

    def do_GET(self):
        cfg = get_config()
        logger = cfg.logger
        try:
            ip_from_headers = self.headers.get("X-Real-IP")
            if ip_from_headers is not None:
                self.client_address = (ip_from_headers, self.client_address[1])
            real_ip = self.headers.get("X-Real-IP") or self.client_address[0]
            fn = ws_endpoints.get("GET", {}).get(self.path)
            if fn is None:
                self.error(404, f"No such WebSocket: '{self.path}'")
                logger.info(f"[{real_ip}] - WS {self.path}: 404")
                return
            try:
                pre = fn(self.headers)
            except Exception as e:
                logger.exception(e)
                self.error(500, f"Server error: {e.__class__.__name__}")
                return
            if not isinstance(pre, dict) or not pre.get("websocket"):
                if isinstance(pre, dict) and "rc" in pre:
                    self.send_response(pre["rc"])
                    self.send_header("Content-type", pre.get("content-type", "application/json"))
                    self._send_cors_headers()
                    self.end_headers()
                    data = pre.get("data", {})
                    body = json.dumps(data) if isinstance(data, dict) else str(data)
                    self.wfile.write(body.encode("utf-8"))
                    self.wfile.flush()
                    return
                self.error(500, "Incorrect output from the endpoint function.")
                return
            if not is_websocket_upgrade(self.headers):
                self.error(426, "This endpoint is a WebSocket. Send Upgrade: websocket.")
                logger.info(f"[{real_ip}] - RQ: GET {self.path}: 426")
                return
            ws = WebSocket(self)
            if not ws.handshake():
                self.error(400, "Bad WebSocket handshake")
                logger.info(f"[{real_ip}] - RQ: GET {self.path}: 400 (websocket handshake)")
                return
            logger.info(f"[{real_ip}] - WS {self.path}: connected")
            try:
                fn(self.headers, ws)
            except Exception as e:
                logger.error(f"[{real_ip}] - WS {self.path}: {e.__class__.__name__}")
                logger.exception(e)
            finally:
                try:
                    if ws.open:
                        ws.close()
                except Exception:
                    pass
                logger.info(f"[{real_ip}] - WS {self.path}: disconnected")
        except Exception as e:
            try:
                self.error(500, f"Server error: {e.__class__.__name__}")
            except Exception:
                pass
            logger.error(f"WS: GET {self.path}: 500 ({e.__class__.__name__})")
            logger.exception(e)


def serve(
    rest_port: int,
    ws_port: int,
    modules,
    *,
    on_start=None,
    bind_host: str = "0.0.0.0",
    rest_handler=None,
    ws_handler=None,
):
    """Register endpoints, optionally run on_start, then block on the REST server."""
    global _ws_listen_port
    cfg = get_config()
    logger = cfg.logger
    logger.info("Initializing REST API...")
    register_endpoints(modules)
    _ws_listen_port = ws_port
    if on_start is not None:
        on_start()
    rest_cls = rest_handler or APIServer
    ws_cls = ws_handler or WSServer
    ws_server = ThreadingWSServer((bind_host, ws_port), ws_cls)
    Thread(name="API-WS", target=ws_server.serve_forever, daemon=True).start()
    logger.info(f"REST listening on port {rest_port} (single-threaded).")
    logger.info(f"WebSocket listening on port {ws_port} (threaded).")
    HTTPServer((bind_host, rest_port), rest_cls).serve_forever()
