package com.fatdog.reverse;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.SigningInfo;

import java.security.MessageDigest;

// 签名校验对抗第一课：运行时核对自身 APK 的签名证书。
// 重打包必换钥匙——证书指纹必然改变，这就是全部抓手的来源。
// 基准哈希拆两半分藏两类（本类持前半 ^0x3C，Vk 持后半 ^0x5A），
// 运行时拼合比对；校验结果只记账不弹窗——提交框锁没锁，玩家自己体会。
public class Wi {
    private Wi() {
    }

    // 信任基准前半（^0x3C 还原）
    static final int[] PA = {
            15,94,94,14,13,15,8,95,93,15,94,13,12,94,93,95,
            88,8,15,5,10,9,88,12,4,15,4,89,90,93,5,12,
    };

    // HMAC 密钥前半（^0x3C 还原）
    static final int[] KA = {122,93,72,88,83,91,99};

    private static volatile boolean checked = false;
    private static volatile boolean verdict = false;

    static String decode(int[] arr, int k) {
        StringBuilder sb = new StringBuilder(arr.length);
        for (int v : arr) sb.append((char) (v ^ k));
        return sb.toString();
    }

    /** 完整信任基准 = 本类前半 + Vk 后半 */
    public static String trust() {
        return decode(PA, 0x3C) + Vk.decode(Vk.PB, 0x5A);
    }

    /** HMAC 密钥 = 本类前半 + Vk 后半 */
    public static String hmacKey() {
        return decode(KA, 0x3C) + Vk.decode(Vk.KB, 0x5A);
    }

    /** 启动时调用：只记账，不弹窗不退出——失败的表现藏在业务层 */
    public static void audit(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            byte[] der;
            if (android.os.Build.VERSION.SDK_INT >= 28) {
                // 新 API：GET_SIGNING_CERTIFICATES / SigningInfo
                PackageInfo pi = pm.getPackageInfo(ctx.getPackageName(),
                        PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo info = pi.signingInfo;
                der = (info.hasMultipleSigners()
                        ? info.getApkContentsSigners()
                        : info.getSigningCertificateHistory())[0].toByteArray();
            } else {
                // 经典姿势：GET_SIGNATURES（API28 起废弃，教学保留）
                @SuppressWarnings("deprecation")
                PackageInfo old = pm.getPackageInfo(ctx.getPackageName(),
                        PackageManager.GET_SIGNATURES);
                der = old.signatures[0].toByteArray();
            }
            verdict = sha256Hex(der).equalsIgnoreCase(trust());
        } catch (Throwable t) {
            verdict = false;   // 任何异常一律按校验失败处理，静默
        }
        checked = true;
    }

    /** 业务点消费：通过才有资格提交 */
    public static boolean passed() {
        return checked && verdict;
    }

    static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest(data)) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
