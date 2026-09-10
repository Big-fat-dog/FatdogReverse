# -*- coding: utf-8 -*-
"""KKL5 诛仙台：业务 DEX 加密烘焙。

用法：
    python gen_kkl5.py --bake build/kkl5dex/dex/classes.dex

产物：
    app/assets/kkl5/ascension_altar.bin        真密文（AES-128-CBC）
    app/assets/kkl5/classes_decoy.dex          假壳（诱饵）

密钥与 libkkl5.so 的 VMP 派生结果一致：
    AES key = 6a3315b12737d2b16d2ed50ddf8d4852
    IV      = SHA256(plain)[:16]
"""
import hashlib
import os
import sys

from Crypto.Cipher import AES

HERE = os.path.dirname(os.path.abspath(__file__))
ASSET_DIR = os.path.join(HERE, "app", "assets", "kkl5")
AES_KEY = bytes.fromhex("6a3315b12737d2b16d2ed50ddf8d4852")
DECOY_MAGIC = b"ZhuXianTai:DecoyShell"


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def encrypt_dex(plain: bytes) -> bytes:
    iv = hashlib.sha256(plain).digest()[:16]
    ct = AES.new(AES_KEY, AES.MODE_CBC, iv).encrypt(pkcs7_pad(plain))
    return iv + ct


def bake(dex_path: str) -> None:
    with open(dex_path, "rb") as f:
        plain = f.read()
    os.makedirs(ASSET_DIR, exist_ok=True)
    sealed = encrypt_dex(plain)
    out = os.path.join(ASSET_DIR, "ascension_altar.bin")
    with open(out, "wb") as f:
        f.write(sealed)
    decoy = os.path.join(ASSET_DIR, "classes_decoy.dex")
    with open(decoy, "wb") as f:
        f.write(DECOY_MAGIC + b"\n" + bytes((i * 7 + 3) & 0xFF for i in range(1024)))
    print("KKL5 seal: %s (%d -> %d bytes)" % (out, len(plain), len(sealed)))
    print("KKL5 decoy: %s" % decoy)


def main() -> None:
    if len(sys.argv) >= 3 and sys.argv[1] == "--bake":
        bake(sys.argv[2])
        return
    print(__doc__)
    sys.exit(1)


if __name__ == "__main__":
    main()
