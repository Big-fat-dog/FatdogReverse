function list_all_threads() {
    console.log("\n===== 所有线程 comm =====");
    var opendir = new NativeFunction(Module.findExportByName(null, "opendir"), 'pointer', ['pointer']);
    var readdir = new NativeFunction(Module.findExportByName(null, "readdir"), 'pointer', ['pointer']);
    var closedir = new NativeFunction(Module.findExportByName(null, "closedir"), 'int', ['pointer']);

    var dirPath = Memory.allocUtf8String("/proc/self/task");
    var dir = opendir(dirPath);
    if (dir.isNull()) { console.log("  打不开"); return; }

    var dent;
    while (!(dent = readdir(dir)).isNull()) {
        var d_name = dent.add(19).readCString();
        if (!d_name || !/^\d+$/.test(d_name)) continue;
        try {
            var f = new File("/proc/self/task/" + d_name + "/comm", "r");
            var comm = f.readLine();
            f.close();
            console.log("  tid=" + d_name + " comm=" + (comm ? comm.trim() : "?"));
        } catch (e) {}
    }
    closedir(dir);
}
setTimeout(list_all_threads, 3000);