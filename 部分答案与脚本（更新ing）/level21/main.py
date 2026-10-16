import time
import hmac
import hashlib
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
BASE = "https://127.0.0.1:8443"
PATH = "/api/tls"
HEADERS = {
    "User-Agent": "Fatdemo/1.0 (Android)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}
TOTAL_PAGES = 100


# 先用 l36 的密钥试试
KEY = b"fatdemo_ssl_hmac"


# ============ sign 生成 ============
def make_sign(page: int, ts: int) -> str:
    """HMAC-SHA256(key, 'page={page}&ts={ts}') → hex"""
    msg = f"page={page}&ts={ts}".encode()
    return hmac.new(KEY, msg, hashlib.sha256).hexdigest()


# ============ 主流程 ============
def main():
    total = 0

    for page in range(1, TOTAL_PAGES + 1):
        ts = int(time.time())
        sign = make_sign(page, ts)

        params = {
            "page": page,
            "ts":   ts,
            "sign": sign,
        }

        try:
            r = requests.get(
                f"{BASE}{PATH}",
                params=params,
                headers=HEADERS,
                verify=False,
                timeout=10,
            )

            try:
                nums = r.json()["nums"]
                total += sum(nums)
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} "
                      f"sum={sum(nums)} sign={sign[:8]}...")
            except Exception as e:
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} "
                      f"resp={r.text[:200]} err={type(e).__name__}")

        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 请求失败: {type(e).__name__} {e}")



    print("总和:", total)


if __name__ == "__main__":
    main()