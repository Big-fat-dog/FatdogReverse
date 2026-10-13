function my_hook() {
    var addr = Module.findBaseAddress("libfern.so");
    console.log(addr);
    // var funcaddress = addr.add(offset);
    // Interceptor.attach(funcaddress, {
    //     onEnter: function (args) {
    //         console.log(1);
    //         var jnienv = args[0];
    //         var jobject = args[1];
    //         console.log(jnienv);
    //         console.log(jobject)
    //         console.log(args[2]);
    //         console.log(args[3]);
    //     },
    //     onLeave: function (retval) {
    //     }

}

function hook_registerNatives() {
    let symbols = Module.enumerateSymbols('libart.so');
    let addrRegisterNatives = null;

    // 遍历所有符号，查找非 CheckJNI 版本的 RegisterNatives
    for (let i = 0; i < symbols.length; i++) {
        let symbol = symbols[i];

        // 确认符合 RegisterNatives 标准的符号（非 CheckJNI 版本）
        if (symbol.name.indexOf("CheckJNI") < 0 &&
            symbol.name.indexOf("RegisterNatives") >= 0) {
            addrRegisterNatives = symbol.address;
            console.log("[+] Found RegisterNatives symbol: " + symbol.name + " at " + symbol.address);
            break;  // 找到第一个匹配的符号即可
        }
    }

    // 如果没有找到 RegisterNatives 地址，返回 null
    if (addrRegisterNatives === null) {
        console.log("[!] No non-CheckJNI RegisterNatives symbol found!");
    }
    return addrRegisterNatives;
}


function get_all_dynamic_methods() {
    var register_address = hook_registerNatives();
    Interceptor.attach(register_address, {
        onEnter: function (args) {
            var jclazz = args[1];
            var methodsPtr = args[2];
            var count = args[3];
            let className = Java.vm.tryGetEnv().getClassName(jclazz); // 获取类名
            console.log("jclass: ", className);
            console.log("count: ", count.toInt32());
            for (let i = 0; i < count.toInt32(); i++) {
                let methodPtr = methodsPtr.add(i * Process.pointerSize * 3);

                let namePtr = Memory.readPointer(methodPtr);
                let sigPtr = Memory.readPointer(methodPtr.add(Process.pointerSize));
                let fnPtr = Memory.readPointer(methodPtr.add(Process.pointerSize * 2));

                let name = Memory.readCString(namePtr); // 方法名称
                let sig = Memory.readCString(sigPtr);   // 方法签名
                // let symbol = DebugSymbol.fromAddress(fnPtr); // 函数符号信息


                // 打印每个 JNI 方法的详细信息
                console.log("[RegisterNatives] Class:", className);
                console.log("  Method: " + name);
                console.log("  Signature: " + sig);
                console.log("  Function Pointer: " + fnPtr);
                // console.log("  Function Symbol: " + symbol);

            }
        },
        onLeave: function (retval) {
        },
    })
}


function hook_dlopen() {
    var dlopen = Module.findExportByName(null, "dlopen");
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            var so_name = args[0].readCString();
            if (so_name.indexOf("libfern") >= 0) {
                console.log(so_name)
                this.hook_true = true;
            }
        },
        onLeave: function (retval) {
            if (this.hook_true) {
                hook_registerNatives()
            }

        }
    });
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function (args) {
            var so_name = args[0].readCString();
            if (so_name.indexOf("libfern") >= 0) {
                console.log(so_name)
                this.hook_true = true;
            }
        }, onLeave: function (retval) {
            if (this.hook_true) {
                hook_registerNatives()
            }
        }
    });
}

my_hook()
get_all_dynamic_methods()
// hook_dlopen()

