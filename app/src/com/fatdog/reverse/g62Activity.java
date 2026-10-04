package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * 扶桑树 KL25 暮雾锁听：内存/线程/结构层 5 路评分阈值制 + 加载期检测。
 * libmist.so 导出九个函数：
 *   int    nativeMapsFrida()          — maps 特征搜索
 *   int    nativeThreadFinger()       — 线程指纹检测
 *   int    nativeAuxvHook()           — auxv/ELF 一致性校验（守卫）
 *   int    nativeThreadCountCheck()   — 线程数一致性（防枚举被 hook）
 *   int    nativeMapsPhantom()        — maps 幻影映射（memfd:/(deleted)）
 *   int    nativeLoadPhase()          — 加载期(.init_array)检测相位
 *   int    nativeFridaDetect()        — 综合检测（评分阈值制，≥2 判检出）
 *   String nativeAnswer()             — 最终答案（加载期命中则永久锁定）
 *   String nativeStatus()             — 检测详情
 *
 * 关键点：① 5 路评分阈值制 ② 检测在 so 加载瞬间(.init_array)已跑完并缓存
 */
public class g62Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL25 · 暮雾锁听（★★★ 五路评分阈值制）\n\n"
                + "libmist.so 导出九个函数：\n"
                + "  int    nativeMapsFrida()\n"
                + "  int    nativeThreadFinger()\n"
                + "  int    nativeAuxvHook()\n"
                + "  int    nativeThreadCountCheck()\n"
                + "  int    nativeMapsPhantom()\n"
                + "  int    nativeLoadPhase()\n"
                + "  int    nativeFridaDetect()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "评分阈值制（5 路命中 ≥2 才判检出）：\n"
                + "  ① maps frida 特征\n"
                + "  ② 线程名指纹\n"
                + "  ③ auxv/ELF 一致性（守卫）\n"
                + "  ④ 线程数一致性（防枚举被 hook）\n"
                + "  ⑤ maps 幻影映射（memfd/(deleted)）\n\n"
                + "★ 本关检测在 so【加载瞬间】(.init_array)就已执行并缓存，\n"
                + "  答案与加载期结果绑定——事后 hook 运行期检测解不开。\n\n"
                + "标记：两个标记一真一假，需仔细辨别");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        // 加载期相位：读这一行会触发 loadLibrary → .init_array 已跑完
        int phase = Rk.nativeLoadPhase();
        final TextView statusTv = new TextView(this);
        statusTv.setText("加载期检测(.init_array)：相位 " + phaseDesc(phase)
                + "（检测在 so 加载那一刻就已完成）\n\n点击「运行检测」查看完整状态");
        statusTv.setTextColor(phase == 2 ? 0xFFFF6B6B : Color.LTGRAY);
        statusTv.setTypeface(Typeface.MONOSPACE);
        statusTv.setTextSize(12);
        statusTv.setGravity(Gravity.CENTER);
        root.addView(statusTv, Ui.fullWidth(6));

        Button runBtn = new Button(this);
        runBtn.setText("运行检测"); Ui.styleButton(runBtn);
        runBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                int result = Rk.nativeFridaDetect();
                if (result == 1) showFridaDetected();
                String status = Rk.nativeStatus();
                statusTv.setText("检测结果: " + (result == 1 ? "检出 Frida" : "未检出") + "\n\n" + status);
                statusTv.setTextColor(result == 1 ? 0xFFFF6B6B : 0xFF51CF66);
            }
        });
        root.addView(runBtn, Ui.wrap(10));

        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入答案（32位 hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        int p = Ui.dp(10);
        ansIn.setPadding(p, p, p, p);
        root.addView(ansIn, Ui.fullWidth(10));

        Button subBtn = new Button(this);
        subBtn.setText("提交答案"); Ui.styleButton(subBtn);
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(g62Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                if (Rk.nativeFridaDetect() == 1) { showFridaDetected(); return; }
                String expected = Rk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(g62Activity.this, "FLAG_18_KL25{mist_locks_the_ears}");
                    PassLog.mark(g62Activity.this, "KL25");
                } else {
                    Toast.makeText(g62Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(g62Activity.this)
                        .setTitle("提示")
                        .setMessage("内存/线程/结构层 · 五路评分阈值制：\n\n"
                                + "① maps frida 特征搜索\n"
                                + "② 线程名指纹（gum-js-loop/pool-frida/linjector）\n"
                                + "③ auxv/ELF 一致性（守卫，不一致才记分）\n"
                                + "④ 线程数一致性：status Threads vs /proc/self/task 目录数\n"
                                + "   （专治 hook opendir/readdir 藏掉 Frida 线程）\n"
                                + "⑤ maps 幻影映射：r-x 段出现 memfd: 或 (deleted)\n\n"
                                + "评分阈值制：命中 ≥2 路才判检出（单路异常不误杀）\n\n"
                                + "★ 时机同 KL24：检测在 so 加载瞬间(.init_array)已跑完并缓存，\n"
                                + "  进关点按钮只是查看结果；hook nativeFridaDetect 返回 0 解不开答案。\n\n"
                                + "静态复刻：SEED = 20280719\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl25, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }

    private static String phaseDesc(int phase) {
        switch (phase) {
            case 2:  return "已命中(2)";
            case 1:  return "干净(1)";
            default: return "未执行(0)";
        }
    }

    private void showFridaDetected() {
        new AlertDialog.Builder(this)
                .setTitle("已被 Frida 检测")
                .setMessage("检测到 Frida 注入！\n\n本关答案与【加载期】检测结果绑定：\n"
                        + "一旦 so 加载时被检出，答案即被永久锁定，事后 hook 运行期检测也解不开。\n\n"
                        + "干净环境下直接计算并提交即可；若确需挂 Frida，须用 spawn 抢在 so 加载前处理 .init_array 中的检测。")
                .setPositiveButton("知道了", null)
                .show();
    }
}
