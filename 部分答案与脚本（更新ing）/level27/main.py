import time
import hmac
import hashlib
import requests
import urllib3
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
BASE = "https://127.0.0.1:8443"
PATH = "/api/l27"
HEADERS = {
    "User-Agent": "Fatdemo/1.0 (Android)",
    "Content-Type": "application/x-www-form-urlencoded",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}
TOTAL_PAGES = 100

# 密钥配置
AES_KEY_ENC = b"fatdemo_aeskey27"  # a7.a()
HMAC_KEY = b"fatdemo_fin_hmac"  # a7.c()

# 响应解密密钥 a7.b()，就是你提供的这串 ASCII 码转出来的字符串
AES_KEY_DEC = b"fatdemo_rspkey27"

TARGET_HASH = "762fbee9bebf4fabcf3a13fbfa4b89f65caa291846aa7967c4f516a32f933bb2"


def native_pack(page: int, ts: int) -> str:
    """请求加密"""
    plaintext = f"page={page}&ts={ts}".encode()
    cipher = AES.new(AES_KEY_ENC, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size)).hex()


def make_sign(enc: str) -> str:
    """生成请求签名"""
    return hmac.new(HMAC_KEY, enc.encode(), hashlib.sha256).hexdigest()


def decrypt_response(resp_text: str) -> list:
    """解密响应并提取 nums"""
    try:
        # 1. 解析外层 JSON 获取 "d"
        enc_hex = json.loads(resp_text).get("d")
        if not enc_hex:
            print("[-] 响应中没有 'd' 字段")
            return []

        # 2. 使用 a7.b() 对应的密钥解密
        cipher = AES.new(AES_KEY_DEC, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(bytes.fromhex(enc_hex)), AES.block_size)
        plain_str = decrypted.decode('utf-8')

        # 3. 按照 "page=x|nums=y,z,w" 的格式解析
        parts = plain_str.split("|")
        if len(parts) != 2 or not parts[0].startswith("page=") or not parts[1].startswith("nums="):
            print("[-] 解密后格式不符合预期:", plain_str)
            return []

        nums_str = parts[1][5:]  # 截掉 "nums="
        return [int(x) for x in nums_str.split(",")]

    except Exception as e:
        print(f"[-] 解密失败: {e}")
        return []


def main():
    total = 0
    for page in range(1, TOTAL_PAGES + 1):
        ts = int(time.time())
        enc = native_pack(page, ts)
        sign = make_sign(enc)

        payload = {
            "page": page, "ts": ts, "enc": enc, "sign": sign,
            "client": "android-fatdemo", "chan": "final", "ver": "2.7", "dev": "0000000000000000"
        }

        try:
            r = requests.post(f"{BASE}{PATH}", data=payload, headers=HEADERS, verify=False, timeout=10)
            nums = decrypt_response(r.text)

            if nums:
                page_sum = sum(nums)
                total += page_sum
                print(f"[{page:3d}/{TOTAL_PAGES}] 成功获取 {len(nums)} 个数字 | 本页和: {page_sum}")
            else:
                print(f"[{page:3d}/{TOTAL_PAGES}] 失败 | 原始响应: {r.text[:100]}")

        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 请求异常: {e}")

        time.sleep(0.05)

    print("\n" + "=" * 40)
    print(f"最终总和: {total}")
    my_hash = hashlib.sha256(str(total).encode('utf-8')).hexdigest()
    print(f"结果哈希: {my_hash}")

    if my_hash == TARGET_HASH:
        print("\n✅ 验证通过！Flag: FLAG_18_L27{capture_then_replicate}")
    else:
        print("\n❌ 验证失败。请检查是否漏页或网络错误。")


if __name__ == "__main__":
    main()