function hook_dlsym(dlsymFuncAddr){
	Interceptor.attach(dlsymFuncAddr, {
        onEnter: function (args) {
            // do something
            this.libAddr = ptr(args[0]) // args[0]是库基址
            this.funcName = ptr(args[1]) // args[1]是函数名
        },
        onLeave: function (retval) {
            // do something
            let module = Process.findModuleByAddress(retval)//this.libAddr
            console.log("function name: ", this.funcName.readCString(),
                        "lib name: ", module.name, //是否可以直接用libAddr.name?
                        "function's memory address: ",retval,
                        "function offset: ", retval.sub(module.base)
            )
        },
    })
}

let dlsymFuncAddr = Module.findExportByName('libdl.so', 'dlsym')
hook_dlsym(dlsymFuncAddr)