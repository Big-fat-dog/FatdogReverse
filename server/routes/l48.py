# -*- coding: utf-8 -*-
"""L48 落日平原 — operator+ 重载路由

HMAC 密钥: Fatdog_calm_2026
sign = HMAC-SHA256(key, "page=N&ts=T")
"""
import hashlib
import hmac
import os
import random
import time

from fastapi import FastAPI, HTTPException, Query

# --------------- 常量 ---------------
SEED48 = 20280501
PAGES48 = 100
PER_PAGE48 = 10
HMAC_KEY48 = b"Fatdog_calm_2026"

_rng48 = random.Random(SEED48)
NUMS48 = [_rng48.randint(1, 100) for _ in range(PAGES48 * PER_PAGE48)]

TS_WINDOW = 600


def _check_ts(ts: int) -> bool:
    return abs(int(time.time()) - ts) <= TS_WINDOW


# --------------- 路由 ---------------

def register(app: FastAPI):

    @app.get("/api/l48")
    async def l48_handler(page: int = Query(1), ts: int = Query(0), sign: str = Query("")):
        if page < 1 or page > PAGES48:
            raise HTTPException(400, "page out of range")
        if not _check_ts(ts):
            raise HTTPException(403, "ts expired")

        msg = f"page={page}&ts={ts}".encode()
        expected = hmac.new(HMAC_KEY48, msg, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(sign, expected):
            raise HTTPException(403, "sign mismatch")

        start = (page - 1) * PER_PAGE48
        nums = NUMS48[start: start + PER_PAGE48]

        return {"page": page, "ts": ts, "nums": nums}
