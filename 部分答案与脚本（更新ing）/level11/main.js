//将字节转为十六进制
function bytesToHex(bytes) {
    var hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

//hook mac
Java.perform(function () {
    var mac = Java.use("javax.crypto.Mac");
    mac.init.overload('java.security.Key').implementation = function (key) {
        console.log(key.getAlgorithm());
        return this.init(key)
    }

    mac.doFinal.overload('[B').implementation = function (bytes) {
        console.log(bytesToHex(bytes));
        // 转成 UTF-8 字符串
        var String = Java.use("java.lang.String");
        try {
            var str = String.$new(bytes, "UTF-8");
            console.log("Input as UTF-8: " + str);
        } catch (e) {
            console.log("Cannot decode as UTF-8");
        }
        return this.doFinal(bytes);
    }
})