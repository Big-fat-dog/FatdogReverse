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

public class kn4Activity extends Activity {
    private EditText input;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("昆仑第四关 · 冰裂缝\n\n"
                + "libgulch.so 导出函数：\n"
                + "String nativeProbe()\n\n"
                + "它先做一次反模拟体检（扫内存映射、查调试器），"
                + "环境干净后才沿「菱形分叉」拼出密钥："
                + "门面用 dlsym 依次摘取 iris / juniper / kindle / larch / marrow 五枚内核，"
                + "其中 iris↔juniper 同源分叉、各带一枚中继，最后归并到 marrow；"
                + "期间还要回调 Java 层的四类取数接口。\n"
                + "六枚 so 缺一不可，四类回调与环境文件桩没补全也拼不出正确密钥。\n"
                + "请提交它返回的完整字符串。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        input = new EditText(this);
        input.setHint("提交 nativeProbe() 返回值");
        input.setLayoutParams(Ui.fullWidth(14));
        box.addView(input);

        Button sub = new Button(this);
        sub.setText("提交");
        sub.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = input.getText().toString().trim();
                if (Ku4.nativeSubmit(s) == 1) {
                    Celebration.show(kn4Activity.this, "FLAG_18_KL4{glacier_crossed_clean}");
                    PassLog.mark(kn4Activity.this, "KL4");
                } else {
                    Toast.makeText(kn4Activity.this, "冰面碎裂了。环境或回调没补全？", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(sub, Ui.wrap(12));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(kn4Activity.this)
                        .setTitle("提示")
                        .setMessage("两道门槛：\n"
                                + "① 反模拟体检：so 读 /proc/self/maps 搜 unidbg/unicorn 特征、"
                                + "读 /proc/self/status 查 TracerPid——unidbg 里用 IOResolver 喂干净的假文件即可过检。\n"
                                + "② 四类跨层回调（比 KL3 多两类）：\n"
                                + "   · GetStaticMethodID + CallStaticObjectMethod → headMark()（String）\n"
                                + "   · GetStaticMethodID + CallStaticIntMethod → forkSeed()（int）\n"
                                + "   · GetStaticFieldID + GetStaticIntField → SPLIT_X（静态 int 字段，非方法）\n"
                                + "   · GetStaticMethodID + CallStaticObjectMethod → saltPlan()（返回 int[]，按数组读）\n"
                                + "再 loadLibrary 全部六枚 so。setVerbose(true) 会打印所有未实现的调用与字段——照着补就行。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kn4, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }
}
