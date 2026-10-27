import hmac
import time
import requests
import hashlib
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
Host = "127.0.0.1:8443"
PATH = "/api/l46"

CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY = r"D:\AppSpider\FatdogReverse\cert\ca.key"
KEY= b"Fatdog_bind"
hex_der = "30820313308201fba00302010202080437cb71610e1066300d06092a864886f70d01010b05003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f69642044656275673020170d3236303930333135353734325a180f32303534303131393135353734325a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730820122300d06092a864886f70d01010105000382010f003082010a0282010100d0461f8972714155175cf4608f4058cf5460ee8858b21b8d70870380b78d1700f3613526c28c0e5e0c9fce41a28c30b323075c5af6a52222d37bc705242895c42431e5c180b21ff185168aea97a1278d86fa66e9829ba6f91753779125491d8b1a979ed133c4446f9a54832b6d5b8aa3e812b622610c212df882339ad3ee6ff4dd827b22d20ca11215064fffd48714cea829f7c158813475e84c46ea4a3a3501f6a50daaa0cc3d3e6d2bb06fc8a6fc9cc6748d85ac8ed48a8e471af4d70e31b46576963bdfd5ba3ca760eeb05fa6f0dcd226be044fb21caa6446f6a8b51907a1fe04b13cfcf4fa18d63b4f39d1a8b56a4fbe8789e2923d57898d16659a88bf850203010001a321301f301d0603551d0e0416041464e129594e36d23aa9c5c3312f0695bc9b72c280300d06092a864886f70d01010b0500038201010019f6218f6a357d778c925515e390feab4196a63bd8f91e138cfc3217b5ca6d80f0141328a79b1696d05cdd4a5a759bc61f4cc18d63b3a75377d70fba7ce563b931e7a4db68866778d35b444db83dc585812b1dc5e63711dffdff3e84b47bf3507f9f9139869a4e7a9ac4eb147d7eb84756a70f67c94072446bfe079c4a90232506d1f119e9ac91feb55a602dbd7537e7d06290f1cab2a4c40c32c3db2098d280606cd00e4efc583177f32d9d800792cb5b4ae0003acb586b6073fb7b745a9e5081cb2a3528f96f43d3aba9d944087d6c9d04b92de603597f198ee2412bef5bc2406b004d428cbaf3a8ea2dcd65f36631984e8845a4f460b91d9cb875d40fb37d"

TOTAL_PAGES = 100
CERT_DER = bytes.fromhex(hex_der)
def get_vt():
    return os.urandom(8).hex()

def get_nonce():
    return os.urandom(4).hex()

def derive_key(vt: str) -> bytes:
    """按逆向得到的 sub_F48 逻辑派生 32 字节密钥。"""
    cert_hash = hashlib.sha256(CERT_DER).digest()
    vt_bytes = vt.encode("utf-8")

    return hashlib.sha256(
        cert_hash + KEY + vt_bytes
    ).digest()

def get_sign(page: int, ts: int, vt: str, nonce: str) -> str:
    """计算 HMAC-SHA256 签名。"""
    key_bytes = derive_key(vt)

    msg = (
        f"nonce={nonce}&page={page}&ts={ts}"
    ).encode("utf-8")

    return hmac.new(
        key_bytes,
        msg,
        hashlib.sha256
    ).hexdigest()

def build_param(page: int) -> dict:
    vt = get_vt()
    ts = int(time.time())
    nonce = get_nonce()
    sign = get_sign(page, ts, vt, nonce)

    return {
        "page": str(page),
        "ts": str(ts),
        "vt": vt,
        "nonce": nonce,
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

    response = session.post(url, data=params, timeout=10)
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