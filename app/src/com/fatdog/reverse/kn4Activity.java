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
                + "libkunlun4.so 导出函数：\n"
                + "String nativeProbe()\n\n"
                + "这个函数会检查运行环境：扫内存映射、查调试器。\n"
                + "环境干净返回冰面通行令牌；检测到模拟则冰面碎裂。\n"
                + "请提交它返回的字符串。");
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
                if (s.equals("Fatdog_glacier_unlocked")) {
                    Celebration.show(kn4Activity.this, "FLAG_18_KL4{glacier_crossed_clean}");
                    PassLog.mark(kn4Activity.this, "KL4");
                } else {
                    Toast.makeText(kn4Activity.this, "冰面碎裂了。环境不够干净。", Toast.LENGTH_SHORT).show();
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
                        .setMessage("so 会读 /proc/self/maps 搜 unidbg/unicorn 特征、"
                                + "读 /proc/self/status 查 TracerPid。\n"
                                + "在真机上这些文件天然干净所以能过——但你需要用 unidbg 来分析它。\n"
                                + "unidbg 里用 IOResolver 喂干净的假 maps 和 status 即可过检。\n"
                                + "setVerbose(true) 会告诉你缺哪些文件桩。")
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