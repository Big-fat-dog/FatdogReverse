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

// smali 关卡 2（对应教程 19）：激活码验证，难度中等。
// 期望的激活码不在 Java 层明文里，buildKey() 里有一张异或 0x2A 的密文字节数组，
// 在 smali 里它以 fill-array-data / .array-data 形式出现。
// 解题路线：A) 读 smali 还原激活码，直接输入；
//          B) 把 checkKey() 的 smali 整个方法体改成 const/4 v0, 0x1 + return v0。
public class ActivationRoomActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("本功能需要激活码。输入正确的激活码完成激活。");
        box.addView(tv, Ui.wrap(8));

        final EditText input = new EditText(this);
        input.setHint("activation code");
        input.setLayoutParams(Ui.fullWidth(22));
        box.addView(input);

        Button btn = new Button(this);
        Ui.styleButton(btn);
        btn.setText("激活");
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (checkKey(input.getText().toString())) {
                    Celebration.show(ActivationRoomActivity.this, "FLAG_18_L8{smali_activation_key}");
                    PassLog.mark(ActivationRoomActivity.this, "L8");
                } else {
                    Toast.makeText(ActivationRoomActivity.this,
                            "激活码错误。", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(ActivationRoomActivity.this)
                        .setTitle("提示")
                        .setMessage("apktool 解包后，smali 里有一张 fill-array-data 的字节表，它被异或过。把它还原成字符串，或直接把 checkKey 改成恒返回 true。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_08));

        setContentView(box);
        ThemeKit.apply(this);
    }

    boolean checkKey(String input) {
        byte[] expected = buildKey();
        if (input == null) return false;
        if (input.length() != expected.length) return false;
        byte[] given = input.getBytes();
        for (int i = 0; i < expected.length; i++) {
            if (given[i] != expected[i]) return false;
        }
        return true;
    }

    private byte[] buildKey() {
        byte[] enc = {
                108, 107, 126, 102, 107, 104, 7, 24, 26, 24, 28
        };
        byte[] out = new byte[enc.length];
        for (int i = 0; i < enc.length; i++) {
            out[i] = (byte) (enc[i] ^ 0x2A);
        }
        return out;
    }
}