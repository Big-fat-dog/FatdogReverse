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

public class kn5Activity extends Activity {
    private static final int SEED = 0x20260505;
    private EditText input;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("昆仑最终关 · 登顶\n\n"
                + "libkunlun5.so 导出函数：\n"
                + "String nativeClimb(int seed)\n\n"
                + "回调 Java 层 summitKey() 取前半密钥，与 so 内后半拼合解密。\n"
                + "请提交解密后的明文。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        input = new EditText(this);
        input.setHint("提交解密后的明文");
        input.setLayoutParams(Ui.fullWidth(14));
        box.addView(input);

        Button sub = new Button(this);
        sub.setText("登顶");
        sub.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = input.getText().toString().trim();
                String expect = Ku5.nativeClimb(SEED);
                if (s.equals(expect)) {
                    Celebration.show(kn5Activity.this, "FLAG_18_KL5{summit_reached}");
                    PassLog.mark(kn5Activity.this, "KL5");
                } else {
                    Toast.makeText(kn5Activity.this, "还差一步。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(sub, Ui.wrap(12));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(kn5Activity.this)
                        .setTitle("提示")
                        .setMessage("nativeClimb 回调 summitKey() 取 Fatdog_，"
                                + "与 so 内 summit 拼合解密 XOR 加密的 flag。\n"
                                + "unidbg 补法：AbstractJni override callStaticObjectMethod 拦截回调。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kn5, 140));

        setContentView(box);
        ThemeKit.apply(this);
    }
}