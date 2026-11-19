//frida-server -l 127.0.0.1:1337 直接换端口 过端口检测

//头铁硬刚端口检测
function Pass_port() {
    var connectaddr = Module.findExportByName("libc.so", "connect");
    console.log("[+] connect Hook 已安装");
    Interceptor.attach(connectaddr, {
        onEnter: function (args) {
            // args[1] 是 sockaddr_in 结构体指针
            var sockAddr = args[1];

            // 读取地址族 (AF_INET = 2)
            var family = sockAddr.readU16();
            if (family !== 2) return; // 只处理 IPv4

            // 读取端口号（网络字节序，需转换）
            var rawPort = sockAddr.add(2).readU16();
            var port = ((rawPort >> 8) & 0xFF) | ((rawPort & 0xFF) << 8);

            // 读取 IP 地址
            var ipBytes = sockAddr.add(4).readByteArray(4);
            var ip = new Uint8Array(ipBytes).join('.');

            // 判断是否命中 Frida 默认端口及本地回环地址
            var fridaPorts = [27042, 27043, 27044];
            if (ip === "127.0.0.1" && fridaPorts.indexOf(port) !== -1) {
                console.log("[*] 拦截到端口探测: " + ip + ":" + port);
                this.shouldBlock = true;
            }
        },
        onLeave: function (retval) {
            // 如果命中了探测，强制返回 -1 (连接失败)
            if (this.shouldBlock) {
                retval.replace(-1);
                console.log("[*] 已将 connect 返回值篡改为 -1，绕过检测");
            }
        }
    })
}

Pass_port()

//牛皮，啥回复也没有，是不是frida高版本不采用dbus协议了？
//https://cyrus-studio.github.io/blog/posts/%E5%9F%BA%E4%BA%8E-tcpdump-%E8%A7%A3%E6%9E%90-frida-%E9%80%9A%E4%BF%A1%E5%8D%8F%E8%AE%AE%E5%AE%9E%E7%8E%B0-frida-server-%E7%AB%AF%E5%8F%A3%E6%89%AB%E6%8F%8F%E4%B8%8E%E7%BB%95%E8%BF%87/
//还真是换成websocket了。16+版本。
//ps:这个大佬的博客里都是好东西啊。
function pass_dbus() {
    var recvPtr = Module.findExportByName("libc.so", "recv");
    console.log("[+] recv Hook 已安装");
    if (recvPtr) {
        Interceptor.attach(recvPtr, {
            onEnter: function (args) {
                this.buf = args[1]; // 接收缓冲区指针
                this.len = args[2].toInt32(); // 请求读取的长度
            },
            onLeave: function (retval) {
                // 如果读取成功（返回值 > 0），检查内容
                if (retval.toInt32() > 0 && this.buf && !this.buf.isNull()) {
                    try {
                        var data = this.buf.readCString();
                        // 如果收到了 Frida 的特征回复 "REJECT"
                        if (data && data.indexOf("REJECT") !== -1) {
                            // 将缓冲区内容篡改为空或无害字符串
                            this.buf.writeUtf8String("");
                            // 或者将返回值改为 -1，模拟读取失败
                            // retval.replace(-1);
                            console.log("[*] 已拦截 recv 中的 REJECT 特征");
                        }
                    } catch (e) {
                        // 忽略读取错误
                    }
                }
            }
        });

    }
}
pass_dbus()

//主动调用拿答案。
function print_ans(){
    var address = Module.findBaseAddress('libfox.so')
    var funcaddr = address.add(0x14D4)
    var JNIEnv = Java.vm.getEnv()
    var func = new NativeFunction(funcaddr , 'pointer',['pointer', 'pointer'])
    var jstringRet = func(JNIEnv, ptr(0));
    //JNIEnv->GetStringUTFChars(env, jstring, isCopy),反过来利用一下。
    console.log(JNIEnv.getStringUtfChars(jstringRet, null).readCString())
}
