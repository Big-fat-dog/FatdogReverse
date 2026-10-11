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

public class kn5Activity extends Activity {
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
                + "libspire.so 导出函数：\n"
                + "String nativeClimb()\n\n"
                + "门面先做三路反模拟体检（内存映射 / 调试器 / 进程名），"
                + "环境干净后向 Java 层索取五类数据——种子、掩码串、静态标签字段、"
                + "64 位戳、以及一份六段盐；随后用这些状态现算一个置换，"
                + "再以「平坦化调度器」按置换依次调用 quarry / ridge / shard / talus / verge 五枚内核。\n"
                + "执行次序不在源码里，藏在运行时的状态表中——要 trace 才看得见。\n"
                + "六枚 so 缺一不可，五类回调与三份环境文件桩没补全也拼不出正确密钥。\n"
                + "请提交 nativeClimb() 返回的完整字符串。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        input = new EditText(this);
        input.setHint("提交 nativeClimb() 返回值");
        input.setLayoutParams(Ui.fullWidth(14));
        box.addView(input);

        Button sub = new Button(this);
        sub.setText("登顶");
        sub.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = input.getText().toString().trim();
                if (Ku5.nativeSubmit(s) == 1) {
                    Celebration.show(kn5Activity.this, "FLAG_18_KL5{summit_reached}");
                    PassLog.mark(kn5Activity.this, "KL5");
                } else {
                    Toast.makeText(kn5Activity.this, "峰顶还没到。次序或环境没补全？", Toast.LENGTH_SHORT).show();
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
                        .setMessage("三关里补环境最多的一关：\n"
                                + "① 三路反模拟体检：/proc/self/maps（搜 unidbg/unicorn/frida/qemu）、"
                                + "/proc/self/status（TracerPid）、/proc/self/cmdline（搜 unidbg/android_server/frida）"
                                + "——unidbg 里用 IOResolver 喂三份干净的假文件即可过检。\n"
                                + "② 五类跨层回调（比 KL4 多一类）：\n"
                                + "   · CallStaticIntMethod → climbSeed()（int）\n"
                                + "   · CallStaticObjectMethod → baseMark()（String）\n"
                                + "   · GetStaticObjectField → SUMMIT_TAG（静态 String 字段，非方法）\n"
                                + "   · CallStaticLongMethod → peakStamp()（long）\n"
                                + "   · CallStaticObjectMethod → routePlan()（返回 int[]，长度必须为 6）\n"
                                + "③ 平坦化调度器：内核执行次序由运行时状态现算，静态读不到——"
                                + "用 unidbg trace 或 Frida Stalker 跟一遍 dispatcher 看派发次序。\n"
                                + "再 loadLibrary 全部六枚 so。setVerbose(true) 会打印所有未实现的调用与字段——照着补就行。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kn5, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }
}
