import time
import hashlib
import requests
def fatdecode(old_bytes:[],num):
    new_bytes=[]
    for byte in old_bytes:
        new_bytes.append(byte^num)
    return bytes(new_bytes).decode('utf8')


def buildReqKey():
    k1B = [78, 89, 77, 99, 14, 12, 14, 10]
    Ra = [60, 59, 46, 62, 63, 55, 53, 5, 40, 57, 110, 5]
    str1 = fatdecode(Ra,90)
    str2 = fatdecode(k1B,60)
    return (str1+str2).encode('utf8')

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def buildSigSecret():
    SA = [27, 28, 9, 25, 24, 16, 18, 34, 15, 30, 73]
    SB=[99, 79, 85, 91, 99, 79, 93, 80, 72]
    str1 = fatdecode(SA,125)
    str2 = fatdecode(SB,60)
    return str1+str2

#响应解密密钥生成
def buildRspKey():
    KA=[13, 10, 31, 15, 14, 6, 4, 52, 25, 8, 95, 52]
    K2B= [35, 34, 33, 14, 99, 97, 99, 103]
    str1 = fatdecode(KA,107)
    str2 = fatdecode(K2B,81)
    return (str1+str2).encode('utf8')

def main():
    sum=0
    for i in range(1,61):
        data="page=" + str(i) + "&ts=" + str(int((time.time())))
        payload = rc4(buildReqKey(), data.encode('utf8')).hex()
        # print(payload)
        sb = payload+buildSigSecret()
        sgin = hashlib.md5(sb.encode()).hexdigest()
        url = "http://127.0.0.1:8787/api/rc4"
        params = {
            "payload": payload,
            "sig": sgin,
        }
        headers = {
            "User-Agent": "Fatdemo/1.0 (Android)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
        }

        resp = requests.get(url, params=params, headers=headers)
        datas = resp.json()['d']
        target = rc4(buildRspKey(), bytes.fromhex(datas)).decode('utf8').split('|')[-1]
        nums = [int(x) for x in target.split('=')[1].split(',')]
        for num in nums:
            sum+=num
    print(sum)


if __name__ == '__main__':
    main()