package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

/**
 * L52 冰封雪域（★★★★★ 魔改 SM4 + 深层调用栈 + 海量业务代码 · 3 SO 分离）
 *
 * 考点：
 *   - 魔改 SM4（S盒4处换值 + FK异或 + CK循环左移）
 *   - 深层调用栈（5+ 层）
 *   - 3 SO 分离（native52 + native52k + native52b）
 *   - HMAC-SHA256 签名
 *   - 海量业务代码干扰（8 个类）
 */
public class x52Activity extends Activity {

    private EditText sumBox;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("L52 · 冰封雪域（★★★★★ 魔改 SM4 · 3 SO 分离）\n\n"
                + "魔改 SM4 加密 + HMAC-SHA256 签名，深层调用栈（5+ 层）。\n"
                + "3 个 SO 协同：native52（主入口+SM4）+ native52k（密钥+RC4）+ native52b（业务干扰）\n\n"
                + "请求：GET /api/l52?page=N&ts=T&enc=hex(SM4(key, payload))&sign=HMAC(key, payload)\n"
                + "响应：明文 JSON {page, nums}（无加密）\n\n"
                + "100 页取数，每页 10 个数，求和后提交。");
        tv.setGravity(Gravity.CENTER);
        tv.setTextColor(Color.WHITE);
        tv.setTextSize(14);
        root.addView(tv, Ui.wrap(6));

        int p = Ui.dp(10);

        sumBox = new EditText(this);
        sumBox.setHint("100 页数字总和");
        sumBox.setTextColor(Color.WHITE);
        sumBox.setTypeface(Typeface.MONOSPACE);
        sumBox.setBackgroundColor(0x33FFFFFF);
        sumBox.setPadding(p, p, p, p);
        root.addView(sumBox, Ui.fullWidth(10));

        Button submit = new Button(this);
        submit.setText("提交总和");
        Ui.styleButton(submit);
        submit.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String s = sumBox.getText().toString().trim();
                if (s.isEmpty()) {
                    Toast.makeText(x52Activity.this, "请输入总和", Toast.LENGTH_SHORT).show();
                    return;
                }
                int sum;
                try { sum = Integer.parseInt(s); }
                catch (NumberFormatException e) {
                    Toast.makeText(x52Activity.this, "请输入整数", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (sum == 50247) {
                    Celebration.show(x52Activity.this, "FLAG_18_L52{frozen_snowfield}");
                    PassLog.mark(x52Activity.this, "L52");
                } else {
                    Toast.makeText(x52Activity.this, "总和不对，再算算", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(submit, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(x52Activity.this)
                    .setTitle("提示")
                    .setMessage("静态：IDA 识别魔改 SM4（S 盒 4 处换值 0x3A/0x7F/0xB2/0xE8，FK 异或，CK 循环左移）→ Python 复刻加密 + HMAC 取数。\n\n"
                        + "动态：Frida hook Bk52.nativeSign/nativeEnc 拿明文 payload 对拍 → Python 复刻。\n\n"
                        + "深层栈回溯：Thread.backtrace 追 5+ 层调用链。\n"
                        + "dlopen 依赖：native52 加载 native52k（密钥）和 native52b（业务干扰）。")
                    .setPositiveButton("好的", null)
                    .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        Button back = new Button(this);
        back.setText("返回");
        Ui.styleButton(back);
        back.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { finish(); }
        });
        root.addView(back, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_52, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
