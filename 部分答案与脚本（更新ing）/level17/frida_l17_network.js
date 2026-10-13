// 第17关 网络签名定位脚本
// 策略：先找到网络请求入口，再追踪签名参数的生成

Java.perform(function () {
    console.log("[*] 第17关 网络签名定位脚本已加载");

    // ========== 第一步：hook OkHttp（最常用的网络库）==========
    try {

        var RequestBuilder = Java.use("okhttp3.Request$Builder");

        // hook Request.Builder.url()
        RequestBuilder.url.overload("java.lang.String").implementation = function (url) {
            console.log("\n[URL] " + url);
            // 打印调用栈，看是谁发起的请求
            console.log(Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()));
            return this.url(url);
        };

        // hook Request.Builder.addHeader
        RequestBuilder.addHeader.implementation = function (name, value) {
            console.log("[Header] " + name + ": " + value);
            return this.addHeader(name, value);
        };

        // hook Request.Builder.post
        try {
            RequestBuilder.post.implementation = function (body) {
                console.log("[POST Body] " + body);
                return this.post(body);
            };
        } catch (e) {}

        console.log("[OK] OkHttp hooks installed");
    } catch (e) {
        console.log("[!] OkHttp not found: " + e);
    }

    // ========== 第二步：hook HttpURLConnection（备选）==========
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.setRequestMethod.implementation = function (method) {
            console.log("\n[HttpURLConnection] " + method + " " + this.getURL().toString());
            return this.setRequestMethod(method);
        };

        HttpURLConnection.setRequestProperty.implementation = function (key, value) {
            console.log("[HttpProp] " + key + ": " + value);
            return this.setRequestProperty(key, value);
        };

        console.log("[OK] HttpURLConnection hooks installed");
    } catch (e) {
        console.log("[!] HttpURLConnection hook failed: " + e);
    }

    // ========== 第三步：hook 常见签名相关类（精准范围）==========
    // 只 hook 已知的签名/加密类，不碰通用 String

    // hook MessageDigest（SHA/Md5 签名）
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.update.overload("[B").implementation = function (input) {
            var hex = bytesToHex(input);
            console.log("\n[MessageDigest.update] " + this.getAlgorithm() + " input=" + hex.substring(0, 64) + "...");
            return this.update(input);
        };
        MessageDigest.digest.overload().implementation = function () {
            var result = this.digest();
            console.log("[MessageDigest.digest] result=" + bytesToHex(result));
            return result;
        };
        console.log("[OK] MessageDigest hooks installed");
    } catch (e) {}

    // hook Mac（HMAC 签名）
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.init.overload("java.security.Key").implementation = function (key) {
            var keyBytes = key.getEncoded();
            console.log("\n[Mac.init] algorithm=" + this.getAlgorithm() + " key=" + bytesToHex(keyBytes));
            return this.init(key);
        };
        Mac.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            console.log("[Mac.doFinal] result=" + bytesToHex(result));
            return result;
        };
        console.log("[OK] Mac hooks installed");
    } catch (e) {}

    // hook Cipher（加密/解密）
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key").implementation = function (mode, key) {
            var modeStr = (mode === 1) ? "ENCRYPT" : (mode === 2) ? "DECRYPT" : "UNWRAP";
            console.log("\n[Cipher.init] " + modeStr + " algo=" + this.getAlgorithm());
            return this.init(mode, key);
        };
        Cipher.doFinal.overload("[B").implementation = function (input) {
            console.log("[Cipher.doFinal] input_len=" + input.length);
            var result = this.doFinal(input);
            console.log("[Cipher.doFinal] output_len=" + result.length);
            return result;
        };
        console.log("[OK] Cipher hooks installed");
    } catch (e) {}

    // ========== 辅助函数 ==========
    function bytesToHex(bytes) {
        if (!bytes) return "null";
        var hex = "";
        for (var i = 0; i < bytes.length && i < 32; i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        if (bytes.length > 32) hex += "...(len=" + bytes.length + ")";
        return hex;
    }

    console.log("\n[*] 所有 hook 已安装，现在操作 App 触发网络请求...");
    console.log("[*] 提示：hook 加密算法拿不到结果时，说明签名是在 native 层（SO）计算的");
    console.log("[*] 下一步：用 Frida 的 Interceptor hook JNI 调用");
});
