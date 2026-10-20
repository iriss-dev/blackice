from __future__ import annotations

import json
import logging
import queue
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

from blackice.api.router import ApiRouter

logger = logging.getLogger("blackice.api")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Broadcaster:
    def __init__(self) -> None:
        self._clients: List[queue.Queue] = []
        self._lock = threading.Lock()

    def register(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self._clients.append(q)
        return q

    def unregister(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._clients:
                self._clients.remove(q)

    def broadcast(self, event: Dict[str, Any]) -> None:
        with self._lock:
            for q in list(self._clients):
                try:
                    q.put_nowait(event)
                except queue.Full:
                    pass


class BlackIceHandler(BaseHTTPRequestHandler):
    router: ApiRouter
    broadcaster: Broadcaster

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard HTTP request logging
        pass

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/v1/stream":
            self._handle_sse_stream()
            return

        status, content_type, body = self.router.handle_get(self.path)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length > 0 else b""

        status, content_type, body = self.router.handle_post(self.path, body_bytes)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _handle_sse_stream(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        event_queue = self.broadcaster.register()
        try:
            # Send initial hello
            init_msg = json.dumps({"timestamp": time.time(), "event_type": "CONNECTED", "ip": "127.0.0.1", "message": "Stream connected"})
            self.wfile.write(f"data: {init_msg}\n\n".encode("utf-8"))
            self.wfile.flush()

            while True:
                try:
                    event = event_queue.get(timeout=10.0)
                    line = f"data: {json.dumps(event)}\n\n".encode("utf-8")
                    self.wfile.write(line)
                    self.wfile.flush()
                except queue.Empty:
                    # Keep-alive heartbeat comment
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.broadcaster.unregister(event_queue)


class ApiServer:
    def __init__(self, host: str, port: int, router: ApiRouter, broadcaster: Broadcaster) -> None:
        self.host = host
        self.port = port
        self.router = router
        self.broadcaster = broadcaster
        self._server: Optional[ThreadedHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        class BoundHandler(BlackIceHandler):
            router = self.router
            broadcaster = self.broadcaster

        self._server = ThreadedHTTPServer((self.host, self.port), BoundHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="blackice-api")
        self._thread.start()
        logger.info(f"BlackICE API & Cockpit running at http://{self.host}:{self.port}/")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
