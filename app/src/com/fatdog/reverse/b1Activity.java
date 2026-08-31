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

// Frida 关卡 3（对应教程 20）：AES-CBC 解密校验。
// 输入密码，App 用 SBox 里的密钥/IV 解密一段密文后与你输入比对。
// 注意：本类不再用"关卡名"式命名，真正的内容（密钥、IV、密文）分散在工具类 SBox 里，
//       旁边还有几个看起来像但没人调用的类，别被带偏。
// 解法：静态——去 SBox 找密钥/IV/密文，用 Python 或 jadx 还原密码；
//       动态——Frida Hook javax.crypto.Cipher 的 doFinal，或 Hook verify() 强制通过。
public class b1Activity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("输入正确的密码，打开这座 AES 密码库。");
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
                    Celebration.show(b1Activity.this, "FLAG_18_L12{aes_vault_unlocked}");
                    PassLog.mark(b1Activity.this, "L12");
                } else {
                    Toast.makeText(b1Activity.this,
                            "密码错误。", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(b1Activity.this)
                        .setTitle("提示")
                        .setMessage("密钥、IV、密文都不在本类里。去别的类找，注意那些看起来像工具却没人调用的类。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_12));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }

    boolean verify(String password) {
        try {
            return SBox.decryptVault().equals(password);
        } catch (Exception e) {
            return false;
        }
    }
}