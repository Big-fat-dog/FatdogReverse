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

public class kn2Activity extends Activity {
    private static final int SEED = 0x20260202;
    private EditText input;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("昆仑第二关 · 引雷桩\n\n"
                + "libkunlun2.so 导出函数：\n"
                + "int nativeForge(int seed)\n\n"
                + "请计算 nativeForge(0x20260202) 的返回值（十进制）并提交。\n"
                + "注意：so 里有两个同名/近名的导出函数——只有一个能给出正确答案。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        input = new EditText(this);
        input.setHint("提交 nativeForge 返回值（十进制）");
        input.setLayoutParams(Ui.fullWidth(14));
        box.addView(input);

        Button sub = new Button(this);
        sub.setText("提交");
        sub.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = input.getText().toString().trim();
                if (s.equals(String.valueOf(Ku2.nativeForge(SEED)))) {
                    Celebration.show(kn2Activity.this, "FLAG_18_KL2{thunder_rod}");
                    PassLog.mark(kn2Activity.this, "KL2");
                } else {
                    Toast.makeText(kn2Activity.this, "不对。你是不是调到了诱饵？", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(sub, Ui.wrap(12));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(kn2Activity.this)
                        .setTitle("提示")
                        .setMessage("必须先触发 JNI_OnLoad（里面做了 RegisterNatives），"
                                + "之后 nativeForge 才指向真实现。unidbg 里 dm.callJNI_OnLoad(emulator)。\n"
                                + "跳过这步会命中导出表里的同名诱饵，返回错误答案。\n"
                                + "IDA 看 JNI_OnLoad 的 RegisterNatives 参数即可找到真身地址。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kn2, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }
}