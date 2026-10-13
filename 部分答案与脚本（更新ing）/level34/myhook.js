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

// 用法：
setTimeout(bypassAll,1000,false);   // 不打印
// bypassAll(true);  // 打印
// bypassAll();      // 默认不打印

// 第17关 网络签名定位脚本（增强版：打印密钥/IV/明文/密文）
// 策略：先找到网络请求入口，再追踪签名参数的生成

// Java.perform(function () {
//     console.log("[*] 定位脚本（增强版）已加载");
//
//     // ========== 通用工具 ==========
//     function bytesToHex(bytes, maxLen) {
//         if (!bytes) return "null";
//         maxLen = maxLen || 64;
//         var hex = "";
//         for (var i = 0; i < bytes.length && i < maxLen; i++) {
//             hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
//         }
//         if (bytes.length > maxLen) hex += "...(len=" + bytes.length + ")";
//         return hex;
//     }
//
//     function bytesToStr(bytes) {
//         if (!bytes) return "null";
//         try {
//             // 尝试按 UTF-8 转字符串，失败则返回 hex
//             var StringCls = Java.use("java.lang.String");
//             return StringCls.$new(bytes);
//         } catch (e) {
//             return bytesToHex(bytes);
//         }
//     }
//
//     function stackTrace() {
//         return Java.use("android.util.Log").getStackTraceString(
//             Java.use("java.lang.Exception").$new()
//         );
//     }
//
//     // ========== 第一步：hook OkHttp ==========
//     try {
//         var RequestBuilder = Java.use("okhttp3.Request$Builder");
//
//         RequestBuilder.url.overload("java.lang.String").implementation = function (url) {
//             console.log("\n[URL] " + url);
//             console.log("[URL Stack]\n" + stackTrace());
//             return this.url(url);
//         };
//
//         RequestBuilder.addHeader.overload("java.lang.String", "java.lang.String").implementation = function (name, value) {
//             console.log("[Header] " + name + ": " + value);
//             // 签名常见 header 名，命中时打印调用栈
//             var lower = name.toLowerCase();
//             if (lower.indexOf("sign") >= 0 || lower.indexOf("token") >= 0 ||
//                 lower.indexOf("auth") >= 0 || lower.indexOf("x-") === 0) {
//                 console.log("[Header Stack]\n" + stackTrace());
//             }
//             return this.addHeader(name, value);
//         };
//
//         try {
//             RequestBuilder.post.implementation = function (body) {
//                 console.log("[POST Body] " + body);
//                 try {
//                     // 尝试打印 body 内容
//                     var Buffer = Java.use("okio.Buffer");
//                     var buffer = Buffer.$new();
//                     body.writeTo(buffer);
//                     console.log("[POST Body Content] " + buffer.readUtf8());
//                 } catch (e) {
//                     console.log("[!] read post body failed: " + e);
//                 }
//                 console.log("[POST Stack]\n" + stackTrace());
//                 return this.post(body);
//             };
//         } catch (e) {}
//
//         console.log("[OK] OkHttp hooks installed");
//     } catch (e) {
//         console.log("[!] OkHttp not found: " + e);
//     }
//
//     // ========== 第二步：hook HttpURLConnection ==========
//     try {
//         var HttpURLConnection = Java.use("java.net.HttpURLConnection");
//
//         HttpURLConnection.setRequestMethod.implementation = function (method) {
//             console.log("\n[HttpURLConnection] " + method + " " + this.getURL().toString());
//             console.log("[HttpURLConnection Stack]\n" + stackTrace());
//             return this.setRequestMethod(method);
//         };
//
//         HttpURLConnection.setRequestProperty.implementation = function (key, value) {
//             console.log("[HttpProp] " + key + ": " + value);
//             var lower = key.toLowerCase();
//             if (lower.indexOf("sign") >= 0 || lower.indexOf("token") >= 0 ||
//                 lower.indexOf("auth") >= 0) {
//                 console.log("[HttpProp Stack]\n" + stackTrace());
//             }
//             return this.setRequestProperty(key, value);
//         };
//
//         console.log("[OK] HttpURLConnection hooks installed");
//     } catch (e) {
//         console.log("[!] HttpURLConnection hook failed: " + e);
//     }
//
//     // ========== 第三步：hook 密钥/IV 构造（重点） ==========
//
//     // SecretKeySpec：对称加密密钥
//     try {
//         var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
//         SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
//             console.log("\n[SecretKeySpec] algo=" + algo +
//                         " key_hex=" + bytesToHex(key) +
//                         " key_str=" + bytesToStr(key));
//             console.log("[SecretKeySpec Stack]\n" + stackTrace());
//             return this.$init(key, algo);
//         };
//         console.log("[OK] SecretKeySpec hooks installed");
//     } catch (e) {
//         console.log("[!] SecretKeySpec hook failed: " + e);
//     }
//
//     // IvParameterSpec：AES/DES 的 IV
//     try {
//         var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
//         IvParameterSpec.$init.overload("[B").implementation = function (iv) {
//             console.log("\n[IvParameterSpec] iv_hex=" + bytesToHex(iv) +
//                         " iv_str=" + bytesToStr(iv));
//             console.log("[IvParameterSpec Stack]\n" + stackTrace());
//             return this.$init(iv);
//         };
//         console.log("[OK] IvParameterSpec hooks installed");
//     } catch (e) {
//         console.log("[!] IvParameterSpec hook failed: " + e);
//     }
//
//     // PBEKeySpec：口令派生
//     try {
//         var PBEKeySpec = Java.use("javax.crypto.spec.PBEKeySpec");
//         PBEKeySpec.$init.overload("[C", "[B", "int", "int").implementation = function (password, salt, iterationCount, keyLength) {
//             console.log("\n[PBEKeySpec] password=" + (password ? new java.lang.String(password) : "null") +
//                         " salt=" + bytesToHex(salt) +
//                         " iter=" + iterationCount +
//                         " keyLen=" + keyLength);
//             console.log("[PBEKeySpec Stack]\n" + stackTrace());
//             return this.$init(password, salt, iterationCount, keyLength);
//         };
//         console.log("[OK] PBEKeySpec hooks installed");
//     } catch (e) {
//         console.log("[!] PBEKeySpec hook failed: " + e);
//     }
//
//     // ========== 第四步：hook 常见签名/加密算法 ==========
//
//     // MessageDigest：MD5/SHA
//     try {
//         var MessageDigest = Java.use("java.security.MessageDigest");
//
//         MessageDigest.update.overload("[B").implementation = function (input) {
//             console.log("\n[MessageDigest.update] algo=" + this.getAlgorithm() +
//                         " input_hex=" + bytesToHex(input) +
//                         " input_str=" + bytesToStr(input));
//             console.log("[MessageDigest Stack]\n" + stackTrace());
//             return this.update(input);
//         };
//
//         MessageDigest.update.overload("[B", "int", "int").implementation = function (input, offset, len) {
//             console.log("\n[MessageDigest.update] algo=" + this.getAlgorithm() +
//                         " offset=" + offset + " len=" + len +
//                         " input_hex=" + bytesToHex(input));
//             return this.update(input, offset, len);
//         };
//
//         MessageDigest.digest.overload().implementation = function () {
//             var result = this.digest();
//             console.log("[MessageDigest.digest] algo=" + this.getAlgorithm() +
//                         " result=" + bytesToHex(result));
//             return result;
//         };
//
//         MessageDigest.digest.overload("[B").implementation = function (input) {
//             var result = this.digest(input);
//             console.log("[MessageDigest.digest] algo=" + this.getAlgorithm() +
//                         " input_hex=" + bytesToHex(input) +
//                         " result=" + bytesToHex(result));
//             return result;
//         };
//
//         console.log("[OK] MessageDigest hooks installed");
//     } catch (e) {
//         console.log("[!] MessageDigest hook failed: " + e);
//     }
//
//     // Mac：HMAC
//     try {
//         var Mac = Java.use("javax.crypto.Mac");
//
//         Mac.init.overload("java.security.Key").implementation = function (key) {
//             var keyBytes = key.getEncoded();
//             console.log("\n[Mac.init] algo=" + this.getAlgorithm() +
//                         " key_hex=" + bytesToHex(keyBytes) +
//                         " key_str=" + bytesToStr(keyBytes));
//             console.log("[Mac.init Stack]\n" + stackTrace());
//             return this.init(key);
//         };
//
//         Mac.update.overload("[B").implementation = function (input) {
//             console.log("[Mac.update] algo=" + this.getAlgorithm() +
//                         " input_hex=" + bytesToHex(input) +
//                         " input_str=" + bytesToStr(input));
//             return this.update(input);
//         };
//
//         Mac.doFinal.overload("[B").implementation = function (input) {
//             console.log("[Mac.doFinal] input_hex=" + bytesToHex(input) +
//                         " input_str=" + bytesToStr(input));
//             var result = this.doFinal(input);
//             console.log("[Mac.doFinal] result=" + bytesToHex(result));
//             return result;
//         };
//
//         Mac.doFinal.overload().implementation = function () {
//             var result = this.doFinal();
//             console.log("[Mac.doFinal] result=" + bytesToHex(result));
//             return result;
//         };
//
//         console.log("[OK] Mac hooks installed");
//     } catch (e) {
//         console.log("[!] Mac hook failed: " + e);
//     }
//
//     // Cipher：AES/DES/RSA
//     try {
//         var Cipher = Java.use("javax.crypto.Cipher");
//
//         Cipher.init.overload("int", "java.security.Key").implementation = function (mode, key) {
//             var modeStr = (mode === 1) ? "ENCRYPT" : (mode === 2) ? "DECRYPT" : ("MODE_" + mode);
//             var keyBytes = key.getEncoded();
//             console.log("\n[Cipher.init] " + modeStr +
//                         " algo=" + this.getAlgorithm() +
//                         " key_hex=" + bytesToHex(keyBytes) +
//                         " key_str=" + bytesToStr(keyBytes));
//             console.log("[Cipher.init Stack]\n" + stackTrace());
//             return this.init(mode, key);
//         };
//
//         Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (mode, key, spec) {
//             var modeStr = (mode === 1) ? "ENCRYPT" : (mode === 2) ? "DECRYPT" : ("MODE_" + mode);
//             var keyBytes = key.getEncoded();
//             console.log("\n[Cipher.init] " + modeStr +
//                         " algo=" + this.getAlgorithm() +
//                         " key_hex=" + bytesToHex(keyBytes) +
//                         " key_str=" + bytesToStr(keyBytes) +
//                         " spec=" + spec);
//             console.log("[Cipher.init Stack]\n" + stackTrace());
//             return this.init(mode, key, spec);
//         };
//
//         Cipher.doFinal.overload("[B").implementation = function (input) {
//             console.log("\n[Cipher.doFinal] algo=" + this.getAlgorithm() +
//                         " input_hex=" + bytesToHex(input) +
//                         " input_str=" + bytesToStr(input));
//             var result = this.doFinal(input);
//             console.log("[Cipher.doFinal] output_hex=" + bytesToHex(result) +
//                         " output_str=" + bytesToStr(result));
//             console.log("[Cipher.doFinal Stack]\n" + stackTrace());
//             return result;
//         };
//
//         console.log("[OK] Cipher hooks installed");
//     } catch (e) {
//         console.log("[!] Cipher hook failed: " + e);
//     }
//
//
//     console.log("\n[*] 所有 hook 已安装，现在操作 App 触发网络请求...");
//     console.log("[*] 关注点：SecretKeySpec / IvParameterSpec 打印密钥和 IV");
//     console.log("[*] 关注点：MessageDigest / Mac / Cipher 打印签名原文和结果");
//     console.log("[*] 若加密算法 hook 不到结果，说明签名在 native 层（SO）计算");
//     console.log("[*] 下一步：用 Frida 的 Interceptor hook JNI 调用");
// });


function hook_sha256(){
    var baseadd = Module.findBaseAddress('libtalon.so');
    var funcadd = baseadd.add(0x2AF4)
    Interceptor.attach(funcadd, {
        onEnter: function (args) {
            console.log("OnEnter:");
            console.log(hexdump(args[0]))
            console.log(hexdump(args[1]))
            this.arg0 = args[0]
            this.arg1 = args[1]
        },
        onLeave: function (retval) {
            console.log("OnLeave:");
            console.log("返回值： ", retval.readPointer())
            console.log(hexdump(this.arg0));
            console.log(hexdump(this.arg1));
        }
    })
}
function look(){

    var baseadd = Module.findBaseAddress('libtalon.so');
    var funcadd = baseadd.add(0x1DE4)
    Interceptor.attach(funcadd, {
        onEnter: function (args) {
            console.log("0x1DE4  OnEnter:");
            console.log(args[2].readPointer())
        },
        onLeave: function (retval) {
        }
    })
}
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
hook_dlopen(look,'libtalon')

// hook_dlopen(hook_sha256,'libtalon')
// hook_sha256();