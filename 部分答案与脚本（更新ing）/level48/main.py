import time
import hmac
import hashlib
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
BASE = "https://127.0.0.1:8443"
PATH = "/api/l48"
HEADERS = {
    "User-Agent": "okhttp/4.12.0",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/x-www-form-urlencoded",
}

TOTAL_PAGES = 100
KEY = b"Fatdog_calm_2026"          # "Fatdog_calm_" + half() 的返回值


# ============ 签名 ============
def sign(page: int, ts: int) -> str:
    # 1. 构造消息
    body = f"page={page}&ts={ts}"

    # 2. 对 body 做 SHA-256，转 hex（64 字符）
    digest = hashlib.sha256(body.encode()).hexdigest()

    # 3. HMAC-MD5，直接输出 32 字符 hex
    sign_val = hmac.new(KEY, digest.encode(), hashlib.md5).hexdigest()
    return sign_val


# ============ 生成一次请求 ============
def make_request(page: int):
    ts = int(time.time() * 1000)          # 毫秒时间戳
    sign_val = sign(page, ts)

    data = {
        "page": page,
        "ts":   ts,
        "sign": sign_val,
    }
    return data


# ============ 主流程 ============
def main():
    total = 0

    for page in range(1, TOTAL_PAGES + 1):
        data = make_request(page)

        try:
            r = requests.post(
                f"{BASE}{PATH}",
                data=data,
                headers=HEADERS,
                verify=False,
                timeout=10,
            )

            try:
                nums = r.json()["nums"]
                total += sum(nums)
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} "
                      f"sum={sum(nums)} sign={data['sign'][:8]}...")
            except Exception as e:
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} "
                      f"resp={r.text[:200]} err={type(e).__name__}")

        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 请求失败: {type(e).__name__} {e}")

    print("总和:", total)


if __name__ == "__main__":
    main()