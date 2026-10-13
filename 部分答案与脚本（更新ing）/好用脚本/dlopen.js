function hook_dlopen(func, bagname) {
    var dlopen = Module.findExportByName(null, "dlopen");
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            var so_name = args[0].readCString();
            if (so_name.indexOf(bagname) >= 0) {
                console.log(so_name)
                this.hook_true = true;
            }
        },
        onLeave: function (retval) {
            if (this.hook_true) {
                func()
                // hook_partb()
            }

        }
    });
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function (args) {
            var so_name = args[0].readCString();
            if (so_name.indexOf(bagname) >= 0) {
                console.log(so_name)
                this.hook_true = true;
            }
        }, onLeave: function (retval) {
            if (this.hook_true) {
                func()
            }
        }
    });
}