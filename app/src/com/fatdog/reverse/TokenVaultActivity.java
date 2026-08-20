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

// 关卡 1：flag 以明文写在 dex 里。
// 玩法：用 jadx 打开 APK 找到本关的 flag，输入后提交；提示按钮只给方向，不给答案。
public class TokenVaultActivity extends Activity {
    private static final String FLAG = "FLAG_18_L1{plain_text_in_dex}";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("使用 jadx 打开 APK，找出本关隐藏的 flag，输入后提交。");
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
                if (FLAG.equals(input.getText().toString().trim())) {
                    Celebration.show(TokenVaultActivity.this, FLAG);
                    PassLog.mark(TokenVaultActivity.this, "L1");
                } else {
                    Toast.makeText(TokenVaultActivity.this, "不对，再找找。", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(TokenVaultActivity.this)
                        .setTitle("提示")
                        .setMessage("flag 以明文写死在代码里。试着在 jadx 里全文搜索 FLAG_18。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_01));

        setContentView(box);
        ThemeKit.apply(this);
    }
}
