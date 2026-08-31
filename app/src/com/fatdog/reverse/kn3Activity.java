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

public class kn3Activity extends Activity {
    private EditText input;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("昆仑第三关 · 渡鸦桥\n\n"
                + "libkunlun3.so 导出函数：\n"
                + "String nativeKey()\n\n"
                + "这个函数会回调 Java 层的 halfA() 方法取前半密钥，"
                + "与 so 内的后半拼成完整密钥后返回。\n"
                + "请提交它返回的完整字符串。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        input = new EditText(this);
        input.setHint("提交 nativeKey() 返回值");
        input.setLayoutParams(Ui.fullWidth(14));
        box.addView(input);

        Button sub = new Button(this);
        sub.setText("提交");
        sub.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = input.getText().toString().trim();
                String expect = Ku3.nativeKey();
                if (s.equals(expect)) {
                    Celebration.show(kn3Activity.this, "FLAG_18_KL3{raven_bridge_crossed}");
                    PassLog.mark(kn3Activity.this, "KL3");
                } else {
                    Toast.makeText(kn3Activity.this, "不对。回调没打通？", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(sub, Ui.wrap(12));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(kn3Activity.this)
                        .setTitle("提示")
                        .setMessage("nativeKey() 内部会调 GetStaticMethodID + CallStaticObjectMethod 来回调 Java 的 halfA()。\n"
                                + "unidbg 运行时你需要在 AbstractJni 子类里 override callStaticObjectMethod 拦截这个回调并返回前半密钥。\n"
                                + "setVerbose(true) 会打印所有未实现的调用——照着补就行。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kn3, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }
}