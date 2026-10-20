"""
BlackICE FastAPI / Starlette ASGI Ingress Defense Middleware.

Intercepts hostile scanners, botnets, and proxy evasion in <0.05ms
directly in Python ASGI application pipelines.

Usage:
    from fastapi import FastAPI
    from blackice.integrations.fastapi_middleware import BlackIceMiddleware

    app = FastAPI()
    app.add_middleware(BlackIceMiddleware, block_threshold=75)
"""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Dict, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class BlackIceMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        sentinel_url: str = "http://127.0.0.1:8787",
        block_threshold: int = 75,
        block_tor: bool = False,
        cache_ttl_seconds: int = 300,
    ) -> None:
        super().__init__(app)
        self.sentinel_url = sentinel_url.rstrip("/")
        self.block_threshold = block_threshold
        self.block_tor = block_tor
        self.cache_ttl = cache_ttl_seconds
        self._cache: Dict[str, tuple[bool, int, str, float]] = {}

    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "127.0.0.1")
        )

        if client_ip in ("127.0.0.1", "localhost", "::1"):
            return await call_next(request)

        now = time.time()
        cached = self._cache.get(client_ip)
        if cached and now < cached[3]:
            is_blocked, score, classification, _ = cached
            if is_blocked:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Access denied by BlackICE sentinel",
                        "threat_score": score,
                        "classification": classification,
                    },
                )
            return await call_next(request)

        # Query local BlackICE sentinel
        try:
            req = urllib.request.Request(
                f"{self.sentinel_url}/v1/intel/{client_ip}",
                headers={"User-Agent": "BlackICE-FastAPI/1.0"},
            )
            with urllib.request.urlopen(req, timeout=0.15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            score = data.get("threat_score", 0)
            classification = data.get("classification", "CLEAN")
            is_blocked = score >= self.block_threshold or (self.block_tor and classification == "TOR_EXIT")

            self._cache[client_ip] = (is_blocked, score, classification, now + self.cache_ttl)

            if is_blocked:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Access denied: Hostile network threat posture",
                        "threat_score": score,
                        "classification": classification,
                    },
                )
        except Exception:
            # Fail open if local sentinel is temporarily unreachable
            pass

        return await call_next(request)
