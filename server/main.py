# -*- coding: utf-8 -*-
"""FatdogReverse 模块化服务端入口

启动方式: python -m server.main
或:       python server/main.py
"""
import sys
import os

# 确保项目根在 sys.path 里（从子目录启动时需要）
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

from fastapi import FastAPI
import uvicorn

app = FastAPI(title="FatdogReverse Server")

# 注册路由
from server.routes import kl_loom
kl_loom.register(app)

# -------- 启动 --------
HOST = "0.0.0.0"
PORT_HTTPS = 8443

if __name__ == "__main__":
    ssl_cert = os.path.join(_root, "certs", "server.crt")
    ssl_key = os.path.join(_root, "certs", "server.key")
    use_ssl = os.path.exists(ssl_cert) and os.path.exists(ssl_key)
    print(f"[server] HTTPS https://{HOST}:{PORT_HTTPS}")
    print(f"[server] SSL: {'ON' if use_ssl else 'OFF (certs not found)'}")
    print(f"[server] Routes: POST/GET /api/kl30 (Protobuf)")
    if use_ssl:
        uvicorn.run(app, host=HOST, port=PORT_HTTPS, ssl_certfile=ssl_cert, ssl_keyfile=ssl_key)
    else:
        uvicorn.run(app, host=HOST, port=PORT_HTTPS)
