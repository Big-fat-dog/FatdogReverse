from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad,unpad
def des3_encrypt(key,plaintext):
    key=key.encode("utf8")+b"\x00" * 5
    plaintext=pad(plaintext.encode(),8)
    # 初始化加密器
    cipher = DES3.new(key, DES3.MODE_ECB)
    # 加密
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()

key = "Fatdog_thunder_2026"
data = "page=1&ts=1794663996"
ciphertext = des3_encrypt(key,data)
print(ciphertext)