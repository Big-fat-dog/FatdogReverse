package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// Frida 关卡 2（对应教程 20）：HMAC-SHA256 验签。
// 本关的 HMAC 密钥与待验明文都按分片异或放在 HmacParts，玩家需要先把
// 两份材料都还原出来；HMAC 只用于证明还原正确，不再靠外部知识猜口令。
// 解法：静态——还原 HmacParts.hmacKey() 与 passPhrase()，Python 复刻；
//       动态——Hook javax.crypto.Mac.init/doFinal 观察密钥与输入。
public class MsgAuthActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("输入正确口令，通过验签后获得 flag。");
        box.addView(tv, Ui.wrap(8));

        final EditText input = new EditText(this);
        input.setHint("passphrase");
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
                        .setMessage("密钥和待验口令都按分片异或存在 HmacParts 里。"
                                + "口令不是外部知识，先把两份材料还原再算 HMAC；"
                                + "也可以 Hook Mac.init 和 doFinal，看 App 实际用的密钥与输入。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_11));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }

    boolean verify(String passphrase) {
        return hmacSha256Hex(passphrase).equals(HmacParts.fingerprint());
    }

    static String hmacSha256Hex(String msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(HmacParts.hmacKey().getBytes("UTF-8"), "HmacSHA256"));
            byte[] d = mac.doFinal(msg.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
