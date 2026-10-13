//hook基本哈希算法和加密算法的通用脚本
function bytesToHex(bytes) {
    var hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

function stackTrace(){
    //用于打印函数调用栈
    var log = Java.use("android.util.Log");
    return log.getStackTraceString(Java.use("java.lang.Exception").$new());
}

function hook_crypto_and_hex() {
    Java.perform(function () {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.digest.overload().implementation = function () {
            var result = this.digest();
            console.log("MessageDigest.digest() 被调用");
            console.log("算法: " + this.getAlgorithm());
            console.log("结果: " + bytesToHex(result));
            console.log("调用栈: " + stackTrace());
            return result;
        }

        // 2. Cipher —— AES / DES / RSA
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            console.log("\n[Cipher] 算法: " + this.getAlgorithm());
            console.log("输入: " + bytesToHex(input));
            console.log("输出: " + bytesToHex(result));
            console.log("调用栈:\n" + stackTrace());
            return result;
        };

        // 3. Mac —— HmacSHA256 / HmacMD5
        var Mac = Java.use("javax.crypto.Mac");
        Mac.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            console.log("\n[Mac] 算法: " + this.getAlgorithm());
            console.log("输入: " + bytesToHex(input));
            console.log("输出: " + bytesToHex(result));
            console.log("调用栈:\n" + stackTrace());
            return result;
        };

        // 4. Base64（很多 sign 最后会 Base64 一下）
        var Base64 = Java.use("android.util.Base64");
        Base64.encodeToString.overload("[B", "int").implementation = function (data, flags) {
            var result = this.encodeToString(data, flags);
            console.log("\n[Base64] 输入: " + bytesToHex(data));
            console.log("输出: " + result);
            console.log("调用栈:\n" + stackTrace());
            return result;
        };

        console.log("Hook 已加载，等待调用...");
    })
}

function main(){
    hook_crypto_and_hex();
}
main();