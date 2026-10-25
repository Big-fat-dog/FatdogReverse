import os
import hashlib
import hmac
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
HOST = "127.0.0.1:8443"
PATH = "/api/l44"

CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY = r"D:\AppSpider\FatdogReverse\cert\ca.key"

TOTAL_PAGES = 100
SIGN_KEY_PREFIX = "Fatdog_forge"

# 必须与 IDA 中 a0123456789abcd 的真实内容一致
HEX_TABLE = "0123456789abcdef"

MASK32 = 0xFFFFFFFF
MASK16 = 0xFFFF
MASK8 = 0xFF


def u32(x: int) -> int:
    return x & MASK32


def u16(x: int) -> int:
    return x & MASK16


def u8(x: int) -> int:
    return x & MASK8


def seed_from_time(now: int) -> int:
    return u32((now & 0xFFFFFFFE) ^ 0x9E3779B9)


def transform(x: int) -> int:
    t = u32(x ^ u32(x << 13))
    return u32(t ^ (t >> 17))


class NativeVT:
    """
    nativeVerdictToken() 的近似模拟。

    state 模拟 dword_9470。
    cert_count 模拟 dword_9440，必须根据 passCert()
    的真实调用次数设置，不能直接假设它等于页码。
    """

    def __init__(self, initial_state: int = 0, cert_count: int = 0):
        self.state = u32(initial_state)
        self.cert_count = u32(cert_count)

    # def next_vt(self) -> str:
    #     if len(HEX_TABLE) < 16:
    #         raise ValueError("HEX_TABLE 必须至少包含 16 个字符")
    #
    #     # 对应 native 在状态为 0 时调用 time(NULL)
    #     now = int(time.time())
    #
    #     v1 = self.state
    #     if v1 == 0:
    #         v1 = seed_from_time(now)
    #
    #     # v4 = v1 ^ (v1 << 13) ^ ((v1 ^ (v1 << 13)) >> 17)
    #     v4 = transform(v1)
    #
    #     # v5 = v4 ^ (32 * v4)
    #     v5 = u32(v4 ^ u32(v4 << 5))
    #     v6 = v5
    #
    #     # native 先保存 v5
    #     self.state = v5
    #
    #     # 如果 v5 为 0，v6 改用备用时间种子
    #     if v5 == 0:
    #         v6 = seed_from_time(int(time.time()))
    #
    #     out = [""] * 16
    #
    #     # v27[0..7]
    #     out[0] = HEX_TABLE[v4 & 0xF]
    #     out[1] = HEX_TABLE[(v5 >> 4) & 0xF]
    #     out[2] = HEX_TABLE[(v5 >> 8) & 0xF]
    #     out[3] = HEX_TABLE[(v5 >> 12) & 0xF]
    #     out[4] = HEX_TABLE[(v5 >> 16) & 0xF]
    #     out[5] = HEX_TABLE[(v5 >> 20) & 0xF]
    #     out[6] = HEX_TABLE[(v5 >> 24) & 0xF]
    #     out[7] = HEX_TABLE[(v5 >> 28) & 0xF]
    #
    #     # v27[8..9]
    #     t6 = u32(v6 ^ u32(v6 << 13))
    #     x = u32(v6 ^ (t6 >> 17))
    #     x = u32(x ^ u32(x << 5))
    #     mixed_byte = u8(x ^ u8(-71 * self.cert_count))
    #
    #     out[8] = HEX_TABLE[mixed_byte & 0xF]
    #     out[9] = HEX_TABLE[(mixed_byte >> 4) & 0xF]
    #
    #     # native 第二次状态更新：
    #     # dword_9470 = transform(v6) ^ (32 * transform(v6))
    #     transformed = transform(v6)
    #     self.state = u32(transformed ^ u32(transformed << 5))
    #
    #     # v14 和 v20
    #     v14 = u32(
    #         self.state ^ u32(-1640531527 * self.cert_count)
    #     )
    #     v20 = u16(
    #         self.state ^ u32(31161 * self.cert_count)
    #     )
    #
    #     # v27[10..15]
    #     out[10] = HEX_TABLE[(v14 >> 8) & 0xF]
    #     out[11] = HEX_TABLE[(v20 >> 12) & 0xF]
    #     out[12] = HEX_TABLE[(v14 >> 16) & 0xF]
    #     out[13] = HEX_TABLE[(v14 >> 20) & 0xF]
    #     out[14] = HEX_TABLE[(v14 >> 24) & 0xF]
    #     out[15] = HEX_TABLE[(v14 >> 28) & 0xF]
    #
    #     return "".join(out)

    def new_vt(self) -> str:
        """8 字节随机数 -> 16 位小写 hex"""
        return os.urandom(8).hex()


def sign_for(page: int, ts: int, vt: str) -> str:
    # 对应 Java:
    # sha256Of("Fatdog_forge|" + vt)
    key_raw = f"{SIGN_KEY_PREFIX}|{vt}"
    hmac_key = hashlib.sha256(
        key_raw.encode("utf-8")
    ).hexdigest().encode("ascii")

    # 对应 Java: "page=" + i + "&ts=" + j
    message = f"page={page}&ts={ts}".encode("utf-8")

    return hmac.new(
        hmac_key,
        message,
        hashlib.sha256
    ).hexdigest()


def build_params(page: int, vt_generator: NativeVT) -> dict:
    # Java 调用顺序：先获取 vt，再获取 ts
    # vt = vt_generator.next_vt()
    vt = vt_generator.new_vt()
    ts = int(time.time() * 1000) // 1000
    sign = sign_for(page, ts, vt)

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


def fetch_page(
    session: requests.Session,
    page: int,
    vt_generator: NativeVT,
):
    params = build_params(page, vt_generator)
    url = f"https://{HOST}{PATH}"

    print(
        f"[请求] page={params['page']} "
        f"ts={params['ts']} "
        f"vt={params['vt']} "
        f"sign={params['sign']}"
    )

    response = session.get(url, params=params, timeout=10)
    return response


def main():
    session = make_session()

    # 模拟进程启动时的 native 状态
    vt_generator = NativeVT(
        initial_state=0,
        cert_count=0,
    )

    grand_total = 0

    for page in range(1, TOTAL_PAGES + 1):
        try:
            response = fetch_page(session, page, vt_generator)

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
