# -*- coding: utf-8 -*-
"""KL30 天机织锦 — Protobuf 二进制协议路由

Protobuf schema:
    PageRequest  { page: uint32 = 1; ts: uint64 = 2; }
    PageResponse { code: uint32 = 1; nums: repeated int32 = 2; sign: bytes = 3; }

HMAC 签名: HMAC-SHA256(Fatdog_weave, response_body_bytes)
"""
import hashlib
import hmac
import os
import random
import struct
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

# --------------- 常量 ---------------
SEED30 = 20280724
PAGES30 = 100
PER_PAGE30 = 10
HMAC_KEY = b"Fatdog_weave"

_rng30 = random.Random(SEED30)
NUMS30 = [_rng30.randint(1, 100) for _ in range(PAGES30 * PER_PAGE30)]

# --------------- Protobuf 手写编解码 ---------------

def _encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    out = []
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def _encode_field_varint(field_number: int, value: int) -> bytes:
    tag = (field_number << 3) | 0  # wire type 0 = varint
    return _encode_varint(tag) + _encode_varint(value)


def _encode_field_bytes(field_number: int, data: bytes) -> bytes:
    tag = (field_number << 3) | 2  # wire type 2 = length-delimited
    return _encode_varint(tag) + _encode_varint(len(data)) + data


def encode_page_request(page: int, ts: int) -> bytes:
    return _encode_field_varint(1, page) + _encode_field_varint(2, ts)


def encode_page_response(code: int, nums: list, sign: bytes) -> bytes:
    body = _encode_field_varint(1, code)
    for n in nums:
        body += _encode_field_varint(2, n)
    body += _encode_field_bytes(3, sign)
    return body


def _decode_varint(data: bytes, offset: int) -> tuple:
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        result |= (b & 0x7F) << shift
        offset += 1
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, offset


def decode_page_request(data: bytes) -> dict:
    page = 0
    ts = 0
    offset = 0
    while offset < len(data):
        tag, offset = _decode_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            value, offset = _decode_varint(data, offset)
            if field_number == 1:
                page = value
            elif field_number == 2:
                ts = value
        else:
            break  # unknown wire type
    return {"page": page, "ts": ts}


# --------------- 路由 ---------------

def register(app: FastAPI):

    @app.post("/api/kl30")
    async def kl30_handler(request: Request):
        body = await request.body()
        req = decode_page_request(body)
        page = req["page"]
        ts = req["ts"]

        if page < 1 or page > PAGES30:
            raise HTTPException(400, "page out of range")
        if abs(int(time.time()) - ts) > 600:
            raise HTTPException(403, "ts expired")

        start = (page - 1) * PER_PAGE30
        nums = NUMS30[start: start + PER_PAGE30]

        # 响应体 = protobuf(code=0, nums=nums)
        resp_body = encode_page_response(0, nums, b"")
        sign = hmac.new(HMAC_KEY, resp_body, hashlib.sha256).digest()
        resp_body = encode_page_response(0, nums, sign)

        return Response(content=resp_body, media_type="application/octet-stream")

    @app.get("/api/kl30")
    async def kl30_get(page: int = Query(1), ts: int = Query(0)):
        if page < 1 or page > PAGES30:
            raise HTTPException(400, "page out of range")
        if abs(int(time.time()) - ts) > 600:
            raise HTTPException(403, "ts expired")

        start = (page - 1) * PER_PAGE30
        nums = NUMS30[start: start + PER_PAGE30]

        resp_body = encode_page_response(0, nums, b"")
        sign = hmac.new(HMAC_KEY, resp_body, hashlib.sha256).digest()
        resp_body = encode_page_response(0, nums, sign)

        return Response(content=resp_body, media_type="application/octet-stream")
