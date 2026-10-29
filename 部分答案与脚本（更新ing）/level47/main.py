import hmac
import time
import requests
import hashlib
import urllib3
import os
import re
from Crypto.Cipher import AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Host = "127.0.0.1:8443"
PATH = "/api/l47"

CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY = r"D:\AppSpider\FatdogReverse\cert\ca.key"

KEY = b"Fatdog_seal"

hex_der = (
    "30820313308201fba00302010202080437cb71610e1066300d06092a864886f70d01010b05003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f69642044656275673020170d3236303930333135353734325a180f32303534303131393135353734325a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730820122300d06092a864886f70d01010105000382010f003082010a0282010100d0461f8972714155175cf4608f4058cf5460ee8858b21b8d70870380b78d1700f3613526c28c0e5e0c9fce41a28c30b323075c5af6a52222d37bc705242895c42431e5c180b21ff185168aea97a1278d86fa66e9829ba6f91753779125491d8b1a979ed133c4446f9a54832b6d5b8aa3e812b622610c212df882339ad3ee6ff4dd827b22d20ca11215064fffd48714cea829f7c158813475e84c46ea4a3a3501f6a50daaa0cc3d3e6d2bb06fc8a6fc9cc6748d85ac8ed48a8e471af4d70e31b46576963bdfd5ba3ca760eeb05fa6f0dcd226be044fb21caa6446f6a8b51907a1fe04b13cfcf4fa18d63b4f39d1a8b56a4fbe8789e2923d57898d16659a88bf850203010001a321301f301d0603551d0e0416041464e129594e36d23aa9c5c3312f0695bc9b72c280300d06092a864886f70d01010b0500038201010019f6218f6a357d778c925515e390feab4196a63bd8f91e138cfc3217b5ca6d80f0141328a79b1696d05cdd4a5a759bc61f4cc18d63b3a75377d70fba7ce563b931e7a4db68866778d35b444db83dc585812b1dc5e63711dffdff3e84b47bf3507f9f9139869a4e7a9ac4eb147d7eb84756a70f67c94072446bfe079c4a90232506d1f119e9ac91feb55a602dbd7537e7d06290f1cab2a4c40c32c3db2098d280606cd00e4efc583177f32d9d800792cb5b4ae0003acb586b6073fb7b745a9e5081cb2a3528f96f43d3aba9d944087d6c9d04b92de603597f198ee2412bef5bc2406b004d428cbaf3a8ea2dcd65f36631984e8845a4f460b91d9cb875d40fb37d"
)

TOTAL_PAGES = 100
CERT_DER = bytes.fromhex(hex_der)
CERT_SHA256 = hashlib.sha256(CERT_DER).digest()


# ---------------------------------------------------------------------------
# 密钥派生 / 签名 / 加密  （对应 sub_1A38 / sub_2A64）
# ---------------------------------------------------------------------------

def get_vt() -> str:
    return os.urandom(8).hex()


def derive_key(vt: str) -> bytes:
    """h1 = SHA256(cert_sha256 || b"Fatdog_seal" || vt)"""
    return hashlib.sha256(CERT_SHA256 + KEY + vt.encode("utf-8")).digest()


def aes256_ecb_encrypt_pkcs7(key: bytes, plaintext: bytes) -> bytes:
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len
    return AES.new(key, AES.MODE_ECB).encrypt(padded)


def aes256_ecb_decrypt_pkcs7(key: bytes, ct: bytes) -> bytes:
    padded = AES.new(key, AES.MODE_ECB).decrypt(ct)
    pad_len = padded[-1]
    if not (1 <= pad_len <= 16):
        raise ValueError(f"bad padding byte: {pad_len}")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bad PKCS#7 padding")
    return padded[:-pad_len]


def get_enc(page: int, key: bytes) -> str:
    plaintext = f"page={page}".encode("utf-8")
    return aes256_ecb_encrypt_pkcs7(key, plaintext).hex()


def decrypt_response(d_hex: str, vt: str) -> str:
    key = derive_key(vt)
    ct = bytes.fromhex(d_hex)
    if len(ct) % 16 != 0:
        raise ValueError(f"ciphertext len {len(ct)} not multiple of 16")
    return aes256_ecb_decrypt_pkcs7(key, ct).decode("utf-8", errors="replace")


def get_sign(page: int, ts: int, vt: str) -> str:
    key_bytes = derive_key(vt)
    msg = f"page={page}&ts={ts}".encode("utf-8")
    return hmac.new(key_bytes, msg, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# 请求
# ---------------------------------------------------------------------------

def build_param(page: int) -> dict:
    vt = get_vt()
    ts = int(time.time())
    return {
        "page": str(page),
        "ts": str(ts),
        "vt": vt,
        "enc": get_enc(page, derive_key(vt)),
        "sign": get_sign(page, ts, vt),
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


def fetch_page(session: requests.Session, page: int):
    params = build_param(page)
    url = f"https://{Host}{PATH}"
    print(f"[请求] page={params['page']} ts={params['ts']} vt={params['vt']}")
    response = session.post(url, data=params, timeout=10)
    return response, params



def parse_nums(plaintext: str):
    """从 'page=N|nums=a,b,c' 里提取 nums 列表"""
    m = re.search(r"nums=([0-9,\-]+)", plaintext)
    if not m:
        return []
    return [int(x) for x in m.group(1).split(",") if x.strip()]


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main():
    grand_total = 0
    page_sums = {}
    session = make_session()

    for page in range(1, 1 + TOTAL_PAGES):
        try:
            response, params = fetch_page(session, page)
            print(f"[{page:3d}/{TOTAL_PAGES}] status={response.status_code}")

            try:
                data = response.json()
            except ValueError:
                print(f"  非 JSON 响应: {response.text[:200]}")
                continue

            d_hex = data.get("d")
            if not d_hex:
                print(f"  无 d 字段: {data}")
                continue

            try:
                plaintext = decrypt_response(d_hex, params["vt"])
            except Exception as e:
                print(f"  解密失败: {type(e).__name__}: {e}")
                continue

            nums = parse_nums(plaintext)
            subtotal = sum(nums)
            page_sums[page] = subtotal
            grand_total += subtotal

            print(f"  明文: {plaintext[:120]}")
            print(f"  本页 nums({len(nums)} 个) 和: {subtotal}")

        except requests.RequestException as exc:
            print(f"[{page:3d}/{TOTAL_PAGES}] 请求失败: {type(exc).__name__}: {exc}")

    print("=" * 60)
    print(f"成功页数: {len(page_sums)}/{TOTAL_PAGES}")
    for p in sorted(page_sums):
        print(f"  page {p:3d}: {page_sums[p]}")
    print("=" * 60)
    print(f"总和: {grand_total}")


if __name__ == "__main__":
    main()