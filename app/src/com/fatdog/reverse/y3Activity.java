package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.net.http.SslError;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

// 网络关卡 23（对应教程 21/WebView 白屏）：H5 页面走 WebView 加载本地 HTTPS，
// 服务端自签证书不在系统信任库里 → onReceivedSslError 里 handler.cancel() → 白屏。
// 解法：Hook WvClient.onReceivedSslError，调用 handler.proceed() 放行。
// 页面加载成功后，App 从 H5 的 #flag 元素取 flag 并通关。
public class y3Activity extends Activity {
    private WebView web;
    private TextView status;
    private boolean awarded = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(14), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("H5 页面只走 WebView 加载，服务器证书却没进系统信任库。\n页面白屏了——找到 WebViewClient 对证书错误的处理，放行它。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        status = new TextView(this);
        status.setText("页面加载中…");
        status.setGravity(Gravity.CENTER);
        status.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(status, Ui.wrap(8));

        web = new WebView(this);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        web.setWebViewClient(new WvClient());
        LinearLayout.LayoutParams wlp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        wlp.topMargin = Ui.dp(6);
        box.addView(web, wlp);

        Button retry = new Button(this);
        retry.setText("重新加载");
        Ui.styleButton(retry);
        retry.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                status.setText("重新加载中…");
                web.loadUrl(Hq.url());
            }
        });
        box.addView(retry, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(y3Activity.this)
                        .setTitle("提示")
                        .setMessage("白屏来自证书校验失败。\nWebView 会把 SSL 错误交给 WebViewClient 的 onReceivedSslError(SslErrorHandler handler) 处理，这里直接把它 cancel 了。\nHook 该方法并调用 handler.proceed() 放行，页面就会出现。\n（页面地址藏在 Hq 类里，是异或后的字节数组。）")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_23, 120));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        web.loadUrl(Hq.url());
    }

    // 具名内部类：Frida 可直接 Java.use 它
    private class WvClient extends WebViewClient {
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            // 关卡核心：证书不被信任时直接取消 → 白屏。
            // 破解点：Hook 本方法，调用 handler.proceed() 放行。
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    status.setText("证书校验失败：页面白屏");
                }
            });
            handler.cancel();
        }

        @Override
        public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
            if (failingUrl != null && failingUrl.equals(Hq.url())) {
                status.setText("白屏：证书校验未通过，加载被拦下");
            }
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            if (awarded || !url.equals(Hq.url())) return;
            // 页面真的出来了：从 H5 里取 #flag 的文本
            view.evaluateJavascript(
                    "(function(){var e=document.getElementById('flag');return e?e.innerText:'';})()",
                    new android.webkit.ValueCallback<String>() {
                        @Override
                        public void onReceiveValue(String value) {
                            if (awarded) return;
                            String flag = value == null ? "" : value.replace("\"", "");
                            if (flag.startsWith("FLAG")) {
                                awarded = true;
                                status.setText("白屏散去，页面出现了！");
                                Celebration.show(y3Activity.this, flag);
                                PassLog.mark(y3Activity.this, "L23");
                            }
                        }
                    });
        }
    }
}
