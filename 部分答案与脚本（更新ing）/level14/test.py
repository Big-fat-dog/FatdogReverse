import base64
from Crypto.Cipher import AES

target = b'GRANTED_2026_OK!'                 # 16 字节
xored  = bytes(b ^ 0x5A for b in target)     # 反向异或（异或的逆就是自己）
encB   = AES.new(b'PIVOT_KEY_B_0001', AES.MODE_ECB).encrypt(xored)
license = base64.b64encode(AES.new(b'PIVOT_KEY_A_0001', AES.MODE_ECB).encrypt(encB)).decode()
print(license)                                # /ypiwyDoIxHtJkdhGceyRw==