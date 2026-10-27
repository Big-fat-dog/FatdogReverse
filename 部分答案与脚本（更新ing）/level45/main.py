import hmac
import time
import requests
import hashlib
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
Host = "127.0.0.1:8443"
PATH = "/api/l45"

CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY = r"D:\AppSpider\FatdogReverse\cert\ca.key"

TOTAL_PAGES = 100
SIGN_KEY_PREFIX = "Fatdog_lurk"

def get_vt():
    return os.urandom(8).hex()

def get_sign(page,time,vt):
    msg = "page=" + str(page) + "&ts=" + str(time)
    bkey = SIGN_KEY_PREFIX + "|" +vt
    key = hashlib.sha256(bkey.encode()).hexdigest()
    return hmac.new(key.encode(),msg.encode(),hashlib.sha256).hexdigest()

def build_param(page):
    vt = get_vt()
    ts = int(time.time() * 1000) // 1000
    sign = get_sign(page,ts,vt)
    return {
        "page": str(page),
        "ts": str(ts),
        "vt": vt,
        "sign": sign,
    }

def make_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.cert = (CLIENT_CERT, CLIENT_KEY)
    session.verify = False
    session.headers.update({
        "User-Agent": "Fatdog/1.0 (Android)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    })
    return session

def fetch_page(session: requests.Session, page):
    params = build_param(page)
    url = f"https://{Host}{PATH}"

    print(
        f"[请求] page={params['page']} "
        f"ts={params['ts']} "
        f"vt={params['vt']} "
        f"sign={params['sign']}"
    )

    response = session.get(url, params=params, timeout=10)
    return response

def main():
    grand_total=0
    session = make_session()
    for page in range(1,1+TOTAL_PAGES):
        try:
            response = fetch_page(session, page)

            print(
                f"[{page:3d}/{TOTAL_PAGES}] "
                f"status={response.status_code} "
                f"resp={response.text[:200]}"
            )

            try:
                data = response.json()
                nums = data.get("nums", [])
                if isinstance(nums, list):
                    grand_total += sum(
                        n for n in nums
                        if isinstance(n, (int, float))
                    )
            except (ValueError, TypeError):
                pass

        except requests.RequestException as exc:
            print(
                f"[{page:3d}/{TOTAL_PAGES}] 请求失败: "
                f"{type(exc).__name__}: {exc}"
            )

    print("=" * 60)
    print(f"总和: {grand_total}")

if __name__ == "__main__":
    main()