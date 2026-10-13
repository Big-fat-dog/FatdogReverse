//frida16不走ptrace了，所以这里写不写无所谓
function bypassPtrace() {
    var ptracePtr = Module.findExportByName("libc.so", "ptrace");

    if (ptracePtr) {
        // 使用 Interceptor.replace 完全替换掉 ptrace 的实现
        Interceptor.replace(ptracePtr, new NativeCallback(function(request, pid, addr, data) {
            console.log("[+] ptrace called - bypassing...");
            console.log("    request: " + request);

            // PTRACE_TRACEME 的常量值通常是 0
            if (request == 0) {
                console.log("    [+] Blocked PTRACE_TRACEME!");
                // 直接返回 0，欺骗 App 说“你已经成功附加自己了”
                return 0;
            }

            // 如果有其他 ptrace 需求，可以在这里放行，或者全部屏蔽
            return 0;

        }, 'long', ['int', 'int', 'pointer', 'pointer']));

        console.log("[+] ptrace bypass applied!");
    } else {
        console.log("[-] ptrace not found");
    }
}

setImmediate(function() {
    bypassPtrace();
});
function bypassThreadCheck() {
    var openat = Module.findExportByName("libc.so", "openat");
    var read = Module.findExportByName("libc.so", "read");

    // 保存打开的文件描述符与路径的映射
    var fdMap = new Map();

    if (openat) {
        Interceptor.attach(openat, {
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[1]);
                this.fd_ptr = null;
            },
            onLeave: function(retval) {
                // 如果打开的是 task 目录下的文件，记录 FD
                if (retval.toInt32() > 0 && this.path && this.path.indexOf("/task/") !== -1) {
                    fdMap.set(retval.toInt32(), this.path);
                }
            }
        });
    }

    if (read) {
        Interceptor.attach(read, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2];
            },
            onLeave: function(retval) {
                if (fdMap.has(this.fd) && retval.toInt32() > 0) {
                    var content = Memory.readUtf8String(this.buf, retval.toInt32());

                    // 检查是否存在敏感线程名
                    if (content.indexOf("gmain") !== -1 ||
                        content.indexOf("gdbus") !== -1 ||
                        content.indexOf("gum-js-loop") !== -1) {

                        // console.log("[*] Hiding thread name: " + content.trim());

                        // 替换为普通线程名，注意长度不要超过原长度太多
                        var fakeName = "jit_thread";
                        Memory.writeUtf8String(this.buf, fakeName);
                        retval.replace(fakeName.length);
                    }
                }
            }
        });
    }
}

setImmediate(bypassThreadCheck);
