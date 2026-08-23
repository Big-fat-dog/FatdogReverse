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

// 昆仑 KL1：山门。解包 APK 取出 libkunlun1.so，用 unidbg 调用
// kl_gate(0x20260101)，把返回的十进制值提交回来。
public class kn1Activity extends Activity {
    private static final int SEED = 0x20260101;

    private EditText input;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("天地秘境 KL1 · 山门（天地秘境）\n\n"
                + "libkunlun1.so 导出函数：\n"
                + "int kl_gate(int seed)\n\n"
                + "请计算 kl_gate(0x20260101) 的返回值（十进制）并提交。\n"
                + "工具不限——但这一关，就是为你手里的 unidbg 准备的。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        input = new EditText(this);
        input.setHint("提交 kl_gate 返回值（十进制）");
        input.setLayoutParams(Ui.fullWidth(14));
        box.addView(input);

        Button sub = new Button(this);
        sub.setText("提交");
        sub.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = input.getText().toString().trim();
                if (s.equals(String.valueOf(Ku1.klGate(SEED)))) {
                    Celebration.show(kn1Activity.this, "FLAG_18_KL1{gate_of_kunlun}");
                    PassLog.mark(kn1Activity.this, "KL1");
                } else {
                    Toast.makeText(kn1Activity.this, "不对。让 so 自己告诉你答案。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(sub, Ui.wrap(12));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(kn1Activity.this)
                        .setTitle("提示")
                        .setMessage("unidbg 十行骨架即可：AndroidEmulatorBuilder.for64Bit().build()"
                                + " → createDalvikVM → loadLibrary(\"libkl1.so\") → 直接调用导出符号 kl_gate。\n"
                                + "本关函数体是 xorshift32 七轮，IDA 里一眼可见——但手算七轮位运算不如让引擎跑一遍。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        setContentView(box);
        ThemeKit.apply(this);
    }
}
