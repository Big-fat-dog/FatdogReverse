function stackTrace() {
    return Java.use("android.util.Log").getStackTraceString(
        Java.use("java.lang.Exception").$new()
    );
}

function hookTextViewSetText() {
    var TextView = Java.use("android.widget.TextView");
    // 拦截 setText(CharSequence) 方法
    TextView.setText.overload('java.lang.CharSequence').implementation = function (text) {
        var textStr = text.toString();
        // 过滤：只抓包含特定关键词的文字，避免日志刷屏

        console.log("============= TextView.setText 被调用 =============");
        console.log("内容: " + textStr);
        console.log("调用栈:\n" + stackTrace());
        console.log("================================================");
        return this.setText(text);
    };
}

hookTextViewSetText();