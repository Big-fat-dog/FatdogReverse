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

// Frida 关卡 4（对应教程 20）：双参数双算法校验。
// 账号走 SignUtil 的 MD5，令牌走 KBox 的 AES 解密，两个都对才算过。
// 一关的内容分散在多个类里：账号逻辑在 SignUtil，令牌逻辑在 KBox，
// 旁边还有几个看起来像工具但没人调用的类。
// 解法：静态——还原 SignUtil 的账号分片 + 解 KBox 的 AES 密文；
//       动态——Frida 同时 Hook MessageDigest 和 Cipher 观察两路输入。
public class k4Activity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("同时提供正确的账号和令牌，通过双重校验后获得 flag。");
        box.addView(tv, Ui.wrap(8));

        final EditText acc = new EditText(this);
        acc.setHint("account");
        acc.setLayoutParams(Ui.fullWidth(22));
        box.addView(acc);

        final EditText tok = new EditText(this);
        tok.setHint("token");
        tok.setLayoutParams(Ui.fullWidth(22));
        box.addView(tok);

        Button btn = new Button(this);
        Ui.styleButton(btn);
        btn.setText("验证");
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (verify(acc.getText().toString(), tok.getText().toString())) {
                    Celebration.show(k4Activity.this, "FLAG_18_L13{dual_param_dual_alg}");
                    PassLog.mark(k4Activity.this, "L13");
                } else {
                    Toast.makeText(k4Activity.this,
                            "账号或令牌错误。", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(k4Activity.this)
                        .setTitle("提示")
                        .setMessage("账号种子在 SignUtil 里分片异或存放，MD5 只是指纹；令牌是 KBox 里的 AES 密文。先用 jadx 的交叉引用排除没人调用的类，别对着摘要猜。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_13));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }

    boolean verify(String account, String token) {
        SignUtil signUtil = SignUtil.getInstance();
        KBox kBox = KBox.getInstance();
        if (!signUtil.checkAccount(account)) return false;
        return kBox.checkToken(token);
    }
}
