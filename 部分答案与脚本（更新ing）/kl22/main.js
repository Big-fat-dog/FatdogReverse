// 绕过 detect_maps_scan 的 read 过滤脚本,这个有点碰运气因为读文件可以是高级IO如fget啥的，这里直接hook open 和 read 的系统调用
//另一个方法是重定向，这个在好用脚本里有
(function() {
    var readPtr = Module.findExportByName("libc.so", "read");
    if (!readPtr) {
        console.log("[!] 找不到 read 函数");
        return;
    }

    // 关键词列表，与检测代码保持一致或更全
    var keywords = ["frida", "gadget", "gum-js-loop", "linjector", "re.frida.server", "frida-agent"];
    // 用于构建正则，注意转义特殊字符（如 .）
    var pattern = new RegExp(keywords.map(function(k) {
        return k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }).join('|'), 'gi');

    Interceptor.attach(readPtr, {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.count = args[2].toInt32();

            // 粗略判断：只处理看起来像在读取 maps 的请求
            // 更严谨的做法可以 hook open 记录 fd，但这里为了简洁直接判断缓冲区特征
            this.shouldCheck = false;
            // 简单策略：如果读取长度较大（通常检测代码会读大块数据），且 fd 有效，就进行检查
            // 检测代码中 MAPS_BUF_SIZE 是 8192，所以通常会读取较大的块
            if (this.fd > 2 && this.count >= 512) {
                this.shouldCheck = true;
            }
        },
        onLeave: function(retval) {
            if (!this.shouldCheck) return;
            var n = retval.toInt32();
            if (n <= 0) return;

            // 读取原始缓冲区内容
            var raw = this.buf.readUtf8String(n);
            if (!raw) return;

            // 检查是否命中关键词
            if (pattern.test(raw)) {
                // 方案 A：直接清空缓冲区（激进，可能导致解析错乱，但能过检测）
                // this.buf.writeUtf8String("\0");
                // retval.replace(0);

                // 方案 B：更安全的做法——将关键词替换为等长无害字符
                // 由于是二进制/文本混合，直接字符串替换可能导致长度变化，破坏内存布局
                // 这里采用简单替换：把关键词字符替换为 'x'，保持长度不变
                var clean = raw.replace(pattern, function(match) {
                    return "x".repeat(match.length); // 等长替换
                });

                // 将清理后的数据写回原缓冲区
                this.buf.writeUtf8String(clean);
                console.log("[*] 已清理 read 缓冲区中的 Frida 特征");
            }
        }
    });
    console.log("[*] read 过滤脚本已加载");
})();
function print_ans(){
    var address = Module.findBaseAddress('libowl.so')
    var funcaddr = address.add(0x1344)
    var JNIEnv = Java.vm.getEnv()
    var func = new NativeFunction(funcaddr , 'pointer',['pointer', 'pointer'])
    var jstringRet = func(JNIEnv, ptr(0));
    //JNIEnv->GetStringUTFChars(env, jstring, isCopy),反过来利用一下。
    console.log(JNIEnv.getStringUtfChars(jstringRet, null).readCString())
}