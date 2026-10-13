import hmac
import hashlib
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KEY = b"Fatdog_gloomy"
HOST = "127.0.0.1:8443"
PATH = "/api/l30"

CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY  = r"D:\AppSpider\FatdogReverse\cert\ca.key"

TOTAL_PAGES = 100


def native_sign(i: int, j: int) -> str:
    msg = f"page={i}&ts={j}".encode()
    return hmac.new(KEY, msg, hashlib.sha256).hexdigest()


def build_url(page: int, ts: int = None) -> str:
    if ts is None:
        ts = int(time.time())
    sign = native_sign(page, ts)
    return f"https://{HOST}{PATH}?page={page}&ts={ts}&sign={sign}"


def make_session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    s.cert = (CLIENT_CERT, CLIENT_KEY)
    s.verify = False
    s.headers.update({
        "User-Agent": "Fatdog/1.0 (Android)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    })
    return s


def fetch_page(session: requests.Session, page: int) -> list:
    url = build_url(page)
    resp = session.get(url, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    return data.get("nums", [])


def main():
    session = make_session()

    grand_total = 0
    per_page = []

    for page in range(1, TOTAL_PAGES + 1):
        try:
            nums = fetch_page(session, page)
            s = sum(nums)
            grand_total += s
            per_page.append((page, nums, s))
            print(f"[{page:3d}/{TOTAL_PAGES}] nums={nums} sum={s}")
        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 失败: {type(e).__name__} {e}")
        time.sleep(0.05)   # 稍微限速，避免被服务端封

    print("=" * 60)
    print(f"总页数: {TOTAL_PAGES}")
    print(f"每页和的总和: {grand_total}")

    # 也可以把每页的和再列一遍
    # for page, nums, s in per_page:
    #     print(page, s)


if __name__ == "__main__":
    main()