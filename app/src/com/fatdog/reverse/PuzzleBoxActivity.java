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

// 关卡 3：字符串被拆散，还掺了异或运算。
// 玩法：把拆散的内容还原成 flag，输入后提交；提示按钮只给方向，不给答案。
public class PuzzleBoxActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("代码里没有完整的 flag，它被拆开又做了运算。把它还原出来，输入后提交。");
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
                if (buildFlag().equals(input.getText().toString().trim())) {
                    Celebration.show(PuzzleBoxActivity.this, buildFlag());
                    PassLog.mark(PuzzleBoxActivity.this, "L3");
                } else {
                    Toast.makeText(PuzzleBoxActivity.this, "不对，再算算。", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(PuzzleBoxActivity.this)
                        .setTitle("提示")
                        .setMessage("注意 (char)('y' ^ 1) 这种写法，每个字符都和一个数异或过。异或的逆运算就是异或本身。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_03));

        setContentView(box);
        ThemeKit.apply(this);
    }

    private String buildFlag() {
        String a = "FLAG_18_L3{";
        String b = String.valueOf((char) ('y' ^ 1))   // x
                 + (char) ('l' ^ 3)                   // o
                 + (char) ('s' ^ 1)                   // r
                 + '_'
                 + (char) ('q' ^ 1)                   // p
                 + (char) ('v' ^ 3)                   // u
                 + (char) ('x' ^ 2)                   // z
                 + (char) ('x' ^ 2)                   // z
                 + (char) ('m' ^ 1)                   // l
                 + (char) ('g' ^ 2);                  // e
        return a + b + "}";
    }
}
