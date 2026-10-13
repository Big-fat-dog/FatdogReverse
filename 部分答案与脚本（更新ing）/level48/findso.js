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

                if (name.indexOf('nativeSign')!==-1) {
                    // 打印每个 JNI 方法的详细信息
                    console.log("[RegisterNatives] Class:", className);
                    console.log("  Method: " + name);
                    console.log("  Signature: " + sig);
                    console.log("  Function Pointer: " + fnPtr);
                    // console.log("  Function Symbol: " + symbol);
                }
            }
        },
        onLeave: function (retval) {
        },
    })
}
// get_all_dynamic_methods();

function hook_dlsym(dlsymFuncAddr){
	Interceptor.attach(dlsymFuncAddr, {
        onEnter: function (args) {
            // do something
            this.libAddr = ptr(args[0]) // args[0]是库基址
            this.funcName = ptr(args[1]) // args[1]是函数名
        },
        onLeave: function (retval) {
            // do something
            if(this.funcName.readCString().indexOf('nativeSign')!==-1){
            let module = Process.findModuleByAddress(retval)//this.libAddr
            console.log("function name: ", this.funcName.readCString(),
                        "lib name: ", module.name, //是否可以直接用libAddr.name?
                        "function's memory address: ",retval,
                        "function offset: ", retval.sub(module.base)
            )
        }}
        ,
    })
}

let dlsymFuncAddr = Module.findExportByName('libdl.so', 'dlsym')
hook_dlsym(dlsymFuncAddr)


function findso(){
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
        console.log(JSON.stringify(modules[i]));
    }
}
