from time import time
import hmac,hashlib
import requests
#请求查询参数很好获得：new URL(str + "/api/page?page=" + i + "&ts=" + jCurrentTimeMillis + "&sign=" + sign(i, jCurrentTimeMillis)).openConnection();
#str不用想也知道是url，所以现在需要的三个参数是page,sign,时间戳

#我们来弄sign
#他是一个hmacsha256哈希了(密钥,请求查询参数)
a_bytes = [90, 93, 72, 88, 89, 81, 83, 99]
b_bytes = [76, 93, 91, 89, 99, 87, 89, 69, 99, 14, 12, 14, 10]
def get_key(t_bytes):
    result = []
    for byte in t_bytes:
        result.append(byte^60)
    return bytes(result)
# print(get_key(a_bytes)+get_key(b_bytes))

def get_sign(msg):
    sign = hmac.new(get_key(a_bytes)+get_key(b_bytes), msg.encode(), hashlib.sha256).hexdigest()
    return sign

def get_params(i):
    t = int(time())
    msg = "page=" + str(i) + "&ts=" + str(t)
    params = {
        "page": i,
        "ts": t,
        "sign": get_sign(msg)
    }
    return params


def main():
    sum = 0
    url = "http://127.0.0.1:8787/api/page"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; MI 8 UD MIUI/V12.5.2.0.QECCNXM)",
        "Accept-Encoding": "gzip",
    }
    for i in range(1,101):
        resp = requests.get(url, params=get_params(i), headers=headers)
        for j in resp.json()["nums"]:
            sum += j
    print(sum)

if __name__ == '__main__':
    main()