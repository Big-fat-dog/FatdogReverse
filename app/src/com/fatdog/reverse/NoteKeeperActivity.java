package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.util.Base64;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

// 关卡 2：flag 穿着一件 Base64 的外套。
// 玩法：识别编码并还原出 flag，输入后提交；提示按钮只给方向，不给答案。
public class NoteKeeperActivity extends Activity {
    // 期望值只在下面这串编码里，还原后与输入比对（明文 flag 不会作为整串出现在 dex 里）
    private static final String ENCODED = "RkxBR18xOF9MMntiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("找出被伪装的 flag，还原成明文后输入提交。");
        box.addView(tv, Ui.wrap(8));

        final EditText input = new EditText(this);
        input.setHint("flag");
        input.setLayoutParams(Ui.fullWidth(22));
        box.addView(input);

        Button submit = new Button(this);
        Ui.styleButton(submit);
        submit.setText("提交");
        submit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (decode().equals(input.getText().toString().trim())) {
                    Celebration.show(NoteKeeperActivity.this, decode());
                    PassLog.mark(NoteKeeperActivity.this, "L2");
                } else {
                    Toast.makeText(NoteKeeperActivity.this, "不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(submit, Ui.wrap(22));

        Button hint = new Button(this);
        Ui.styleButton(hint);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(NoteKeeperActivity.this)
                        .setTitle("提示")
                        .setMessage("有一串以 = 结尾的长字符。它不是加密，只是一种很常见的编码方式——想想它是什么。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_02));

        setContentView(box);
        ThemeKit.apply(this);
    }

    private String decode() {
        return new String(Base64.decode(ENCODED, Base64.DEFAULT));
    }
}
