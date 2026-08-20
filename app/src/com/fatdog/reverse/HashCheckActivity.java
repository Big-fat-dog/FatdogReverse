package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.security.MessageDigest;

// Frida 关卡 1（对应教程 20）：SHA-256 哈希校验。
// 输入口令，App 计算 SHA-256 后与内置哈希比对。
// 解法：静态——找到内置哈希与算法，Python 复刻 / 在线查表 / 猜口令；
//       动态——Frida Hook java.security.MessageDigest 的 update/digest，
//             或直接 Hook 本类的 verify() 强制返回 true。
public class HashCheckActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("输入正确的口令，通过验证后获得 flag。");
        box.addView(tv, Ui.wrap(8));

        final EditText input = new EditText(this);
        input.setHint("password");
        input.setLayoutParams(Ui.fullWidth(22));
        box.addView(input);

        Button btn = new Button(this);
        Ui.styleButton(btn);
        btn.setText("验证");
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (verify(input.getText().toString())) {
                    Celebration.show(HashCheckActivity.this, "FLAG_18_L10{sha256_gate_cleared}");
                    PassLog.mark(HashCheckActivity.this, "L10");
                } else {
                    Toast.makeText(HashCheckActivity.this,
                            "口令错误。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(btn, Ui.wrap(22));

        Button hint = new Button(this);
        Ui.styleButton(hint);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(HashCheckActivity.this)
                        .setTitle("提示")
                        .setMessage("口令是全小写字母。想一想这个系列教程第 20 篇的主角是谁；也可以 Hook SHA-256 观察它的输入输出，或直接让 verify 恒返回 true。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_10));

        setContentView(box);
        ThemeKit.apply(this);
    }

    boolean verify(String password) {
        return sha256Hex(password).equals("db77ca6bb991f807190b0c8cb00c09b74094f089a2efb2a0e629d00540973846");
    }

    static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}