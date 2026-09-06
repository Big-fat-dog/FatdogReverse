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
// 正确口令（种子）被 HashSeed 拆成多段异或藏匿；SHA-256 只做最终完整性校验，
// 不再要求玩家对不可逆摘要做外部知识/查表反推。
// 解法：静态——沿组装链还原 HashSeed.seed()；
//       动态——Frida Hook MessageDigest.update 观察摘要输入，
//             或 Hook verify() 观察入参与返回值（本关不靠强制恒真通关）。
public class HashCheckActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("输入正确口令，通过验证后获得 flag。");
        box.addView(tv, Ui.wrap(8));

        final EditText input = new EditText(this);
        input.setHint("seed");
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
                        .setMessage("口令不是外部知识，而是藏在代码里的种子。"
                                + "SHA-256 不可逆，别对着摘要猜；沿 HashSeed 的组装链把所有异或分片还原。"
                                + "动态路线：Hook MessageDigest.update，直接观察 App 喂给摘要的字节。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_10));

        setContentView(box);
        ThemeKit.apply(this);
    }

    boolean verify(String seed) {
        // 这里只保留种子分片还原结果的摘要指纹；输入必须来自 HashSeed.seed()。
        return sha256Hex(seed).equals(HashSeed.sha256Fingerprint());
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
