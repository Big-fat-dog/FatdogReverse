function bypassAll(verbose) {
    // 默认不打印
    if (verbose === undefined) verbose = false;

    // 日志函数
    var log = verbose ? console.log.bind(console) : function () {};

    var open = Module.findExportByName("libc.so", "open");
    var openat = Module.findExportByName("libc.so", "openat");
    var read = Module.findExportByName("libc.so", "read");
    var fgets = Module.findExportByName("libc.so", "fgets");
    var connect = Module.findExportByName("libc.so", "connect");

    // 等长替换表
    var fakeMap = {
        "gmain":       "jmain",
        "gdbus":       "jdbus",
        "gum-js-loop": "jum-js-loo",
        "pool-frida":  "pool-fridb",
        "frida":       "fridb",
        "gadget":      "jadget"
    };
    var keywords = Object.keys(fakeMap);

    // ========== 1. 端口检测 ==========
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function (args) {
                var sa = args[1];
                var family = sa.readU16();
                if (family === 2) {
                    var port_be = sa.add(2).readU16();
                    var port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
                    if (port === 27042 || port === 27043) {
                        log("[connect] 拦截端口:", port);
                        this.block = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.block) retval.replace(ptr(-1));
            }
        });
    }

    // ========== 2. maps 重定向 ==========
    var fakemaps = null;
    try {
        var context = Java.use('android.app.ActivityThread')
            .currentApplication().getApplicationContext();
        fakemaps = context.getFilesDir().getAbsolutePath() + "/clean_maps.txt";
    } catch (e) {
        fakemaps = "/data/local/tmp/temp";
    }

    function generateCleanMaps() {
        try {
            var real_maps = File.readAllText('/proc/self/maps');
            var clean = real_maps.split('\n').filter(function (line) {
                return line.indexOf('frida') === -1 &&
                       line.indexOf('gmain') === -1 &&
                       line.indexOf('gadget') === -1 &&
                       line.indexOf('gdbus') === -1;
            }).join('\n');
            var f = new File(fakemaps, 'w');
            f.write(clean);
            f.close();
            log("成功写入干净 maps:", fakemaps);
        } catch (e) {
            log("生成 maps 失败:", e);
        }
    }
    generateCleanMaps();

    function redirectMaps(args, index) {
        var path = args[index].readCString();
        if (path && path.indexOf("/maps") !== -1 && path.indexOf("proc") !== -1) {
            log("[*] Redirecting maps:", path);
            args[index] = Memory.allocUtf8String(fakemaps);
        }
    }

    // ========== 3. task 检测 ==========
    var fdMap = new Map();

    function recordFd(retval, path) {
        var fd = retval.toInt32();
        if (fd > 0 && path && path.indexOf("/task/") !== -1) {
            fdMap.set(fd, path);
        }
    }

    function isTaskContent(content) {
        return keywords.some(function (k) { return content.indexOf(k) !== -1; });
    }

    function cleanContent(content) {
        var c = content;
        keywords.forEach(function (k) {
            if (c.indexOf(k) !== -1) {
                c = c.split(k).join(fakeMap[k]);
            }
        });
        return c;
    }

    // ========== 4. Hook open / openat ==========
    if (open) {
        Interceptor.attach(open, {
            onEnter: function (args) {
                this.path = args[0].readCString();
                redirectMaps(args, 0);
            },
            onLeave: function (retval) {
                recordFd(retval, this.path);
            }
        });
    }

    if (openat) {
        Interceptor.attach(openat, {
            onEnter: function (args) {
                this.path = args[1].readCString();
                redirectMaps(args, 1);
            },
            onLeave: function (retval) {
                recordFd(retval, this.path);
            }
        });
    }

    // ========== 5. Hook read ==========
    if (read) {
        Interceptor.attach(read, {
            onEnter: function (args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
            },
            onLeave: function (retval) {
                var n = retval.toInt32();
                if (n <= 0 || n > 4096) return;
                if (!fdMap.has(this.fd)) return;

                var content = this.buf.readCString(n);
                if (!content || !isTaskContent(content)) return;

                var clean = cleanContent(content);
                this.buf.writeUtf8String(clean);
                retval.replace(ptr(clean.length));
                log("[read] 过滤 task:", clean.trim());
            }
        });
    }

    // ========== 6. Hook fgets ==========
    if (fgets) {
        Interceptor.attach(fgets, {
            onEnter: function (args) {
                this.buf = args[0];
                this.stream = args[2];
            },
            onLeave: function (retval) {
                if (retval.isNull()) return;
                var line = this.buf.readCString();
                if (!line || !isTaskContent(line)) return;

                var clean = cleanContent(line);
                this.buf.writeUtf8String(clean);
                log("[fgets] 过滤 task:", clean.trim());
            }
        });
    }

    // ========== 7. Hook pthread_setname_np ==========
    var setname = Module.findExportByName("libc.so", "pthread_setname_np");
    if (setname) {
        Interceptor.attach(setname, {
            onEnter: function (args) {
                var name = args[1].readCString();
                if (!name) return;
                keywords.forEach(function (k) {
                    if (name.indexOf(k) !== -1) {
                        var fake = name.split(k).join(fakeMap[k]);
                        log("[setname] 拦截:", name, "->", fake);
                        args[1].writeUtf8String(fake);
                    }
                });
            }
        });
    }
}