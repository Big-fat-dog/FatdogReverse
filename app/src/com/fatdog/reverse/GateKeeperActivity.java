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

// 关卡 4：输入密码，App 计算 MD5 与内置哈希比对。
// 解题路线：找到内置哈希 e10adc3949ba59abbe56e057f20f883e，
//           在线查表 / 爆破得到密码，或直接读懂判断逻辑。
public class GateKeeperActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("输入正确的密码通过验证，获取 flag。");
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
                String pwd = input.getText().toString();
                if (md5(pwd).equals("e10adc3949ba59abbe56e057f20f883e")) {
                    Celebration.show(GateKeeperActivity.this, "FLAG_18_L4{md5_123456}");
                    PassLog.mark(GateKeeperActivity.this, "L4");
                } else {
                    Toast.makeText(GateKeeperActivity.this,
                            "密码不对，再想想。", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(GateKeeperActivity.this)
                        .setTitle("提示")
                        .setMessage("代码里有一段 32 位十六进制串，它可能是某个密码的摘要。想想怎么从摘要还原（在线查表或爆破）。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_04));

        setContentView(box);
        ThemeKit.apply(this);
    }

    public static String md5(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}