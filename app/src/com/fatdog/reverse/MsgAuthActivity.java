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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// Frida 关卡 2（对应教程 20）：HMAC-SHA256 验签。
// 输入口令，App 用内置密钥算 HMAC-SHA256 后与内置值比对。
// 解法：静态——找到密钥与内置 HMAC，Python 复刻；
//       动态——Frida Hook javax.crypto.Mac 的 doFinal，或 Hook verify() 强制通过。
public class MsgAuthActivity extends Activity {
    private static final byte[] KEY = "fatdemo_hmac_key".getBytes();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("输入正确的口令，通过验签后获得 flag。");
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
                    Celebration.show(MsgAuthActivity.this, "FLAG_18_L11{hmac_sign_passed}");
                    PassLog.mark(MsgAuthActivity.this, "L11");
                } else {
                    Toast.makeText(MsgAuthActivity.this,
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
                new AlertDialog.Builder(MsgAuthActivity.this)
                        .setTitle("提示")
                        .setMessage("口令是 FATLAB 实验室代号的全小写。可以 Hook javax.crypto.Mac 看 App 算的是什么、算出什么。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_11));

        setContentView(box);
        ThemeKit.apply(this);
    }

    boolean verify(String password) {
        return hmacSha256Hex(password).equals("042dab800cab0a8df5cce658e0bc05c68b7e8bcd3e897e887b60c1807c31b77c");
    }

    static String hmacSha256Hex(String msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
            byte[] d = mac.doFinal(msg.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}