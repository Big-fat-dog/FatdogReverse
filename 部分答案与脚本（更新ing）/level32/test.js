// ============================================================
// Frida 模拟 sub_1458 的 5 项检测
// 直接在目标进程里跑，读的是目标进程的 /proc/self
// ============================================================

function check_maps() {
    console.log("\n===== [1] /proc/self/maps 检测 =====");
    var found = false;
    try {
        var f = new File("/proc/self/maps", "r");
        var line;
        while ((line = f.readLine()) !== null) {
            if (line.indexOf("frida") >= 0 || line.indexOf("gadget") >= 0) {
                console.log("  [命中] " + line);
                found = true;
            }
        }
        f.close();
    } catch (e) {
        console.log("  读取失败:", e);
    }
    console.log("  结果:", found ? "检测到 Frida/Gadget" : "干净");
    return found;
}


function check_ports() {
    console.log("\n===== [2] Frida 默认端口检测 =====");
    // 注意：Frida 的 Socket API 在部分版本不可用
    // 这里用 NativeFunction 调 socket/connect
    var socket = new NativeFunction(
        Module.findExportByName(null, "socket"),
        'int', ['int', 'int', 'int']
    );
    var connect = new NativeFunction(
        Module.findExportByName(null, "connect"),
        'int', ['int', 'pointer', 'int']
    );
    var close = new NativeFunction(
        Module.findExportByName(null, "close"),
        'int', ['int']
    );

    var ports = [27042, 27043];
    var found = false;

    ports.forEach(function (port) {
        var fd = socket(2, 1, 0);  // AF_INET, SOCK_STREAM
        if (fd < 0) return;

        // 构造 sockaddr_in: family(2) + port(2) + ip(4) + zero(8)
        var sa = Memory.alloc(16);
        sa.writeU16(2);                          // AF_INET
        // 端口用网络字节序
        sa.add(2).writeU8((port >> 8) & 0xFF);
        sa.add(3).writeU8(port & 0xFF);
        sa.add(4).writeU8(127);                  // 127.0.0.1
        sa.add(5).writeU8(0);
        sa.add(6).writeU8(0);
        sa.add(7).writeU8(1);

        var r = connect(fd, sa, 16);
        if (r === 0) {
            console.log("  [命中] 端口 " + port + " 可连接");
            found = true;
        } else {
            console.log("  端口 " + port + " 不可连接 (r=" + r + ")");
        }
        close(fd);
    });

    console.log("  结果:", found ? "检测到 Frida 端口" : "干净");
    return found;
}


function check_threads() {
    console.log("\n===== [3] /proc/self/task/*/comm 线程名检测 =====");
    var found = false;
    var keywords = ["gum-js-loop", "gmain", "gdbus"];

    var opendir  = new NativeFunction(Module.findExportByName(null, "opendir"),  'pointer', ['pointer']);
    var readdir  = new NativeFunction(Module.findExportByName(null, "readdir"),  'pointer', ['pointer']);
    var closedir = new NativeFunction(Module.findExportByName(null, "closedir"), 'int',     ['pointer']);

    var dirPath = Memory.allocUtf8String("/proc/self/task");
    var dir = opendir(dirPath);
    if (dir.isNull()) { console.log("  打不开 /proc/self/task"); return false; }

    var dent;
    while (!(dent = readdir(dir)).isNull()) {
        var d_name = dent.add(19).readCString();
        if (!d_name || !/^\d+$/.test(d_name)) continue;
        try {
            var f = new File("/proc/self/task/" + d_name + "/comm", "r");
            var comm = f.readLine();
            f.close();
            if (comm) {
                var c = comm.trim();
                keywords.forEach(function (kw) {
                    if (c.indexOf(kw) >= 0) {
                        console.log("  [命中] tid=" + d_name + " comm=" + c);
                        found = true;
                    }
                });
            }
        } catch (e) {}
    }
    closedir(dir);

    console.log("  结果:", found ? "检测到 Frida 线程" : "干净");
    return found;
}


function check_tracerpid() {
    console.log("\n===== [4] /proc/self/status TracerPid 检测 =====");
    var found = false;
    try {
        var f = new File("/proc/self/status", "r");
        var line;
        while ((line = f.readLine()) !== null) {
            if (line.indexOf("TracerPid:") === 0) {
                var pid = parseInt(line.split(":")[1].trim(), 10);
                console.log("  TracerPid = " + pid);
                if (pid !== 0) {
                    console.log("  [命中] 被 ptrace 调试");
                    found = true;
                }
                break;
            }
        }
        f.close();
    } catch (e) {
        console.log("  读取失败:", e);
    }
    console.log("  结果:", found ? "检测到 TracerPid" : "干净");
    return found;
}


// ============================================================
// 主入口
// ============================================================

function run_all_checks() {
    console.log("========================================");
    console.log("模拟 sub_1458 反调试检测");
    console.log("========================================");

    var r1 = check_maps();
    var r2 = check_ports();
    var r3 = check_threads();
    var r4 = check_tracerpid();

    console.log("\n========================================");
    console.log("汇总:");
    console.log("  maps      :", r1);
    console.log("  ports     :", r2);
    console.log("  threads   :", r3);
    console.log("  TracerPid :", r4);
    console.log("  最终标记  :", (r1 || r2 || r3 || r4) ? 1 : 0);
    console.log("========================================");
}

// 延迟执行，等 App 启动完
setTimeout(run_all_checks, 5000);