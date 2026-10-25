from androguard.core.apk import APK
import hashlib
import os


def get_cert_der(apk_path, out_dir="."):
    a = APK(apk_path)

    # 优先取 v3 签名证书，其次 v2，最后回退到 v1
    certs_der = a.get_certificates_der_v3() or a.get_certificates_der_v2()

    if certs_der:
        der_bytes = certs_der[0]
    else:
        certs_v1 = a.get_certificates_v1()
        if not certs_v1:
            raise ValueError("APK 中未找到签名证书")
        der_bytes = certs_v1[0].contents  # DER 编码的字节

    # # 保存到当前目录
    # out_path = os.path.join(out_dir, "cert.der")
    # with open(out_path, "wb") as f:
    #     f.write(der_bytes)

    # print(f"已保存: {out_path}  ({len(der_bytes)} 字节)")
    return der_bytes


# 使用
der_bytes = get_cert_der("FatdogReverse.apk")
print(f"DER 长度: {len(der_bytes)}")
print(f"前16字节: {der_bytes.hex()}")
print(f"SHA-256: {hashlib.sha256(der_bytes).hexdigest()}")