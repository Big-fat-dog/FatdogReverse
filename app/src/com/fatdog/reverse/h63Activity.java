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
 * 扶桑树 KL26 暮霭沉沉：6 路评分阈值制 + 加载期检测。
 * libdusk.so 导出十个函数：
 *   int    nativeTiming()         — timing 侧信道
 *   int    nativeVersion()        — Frida 版本/特征嗅探
 *   int    nativeSmapsDirty()     — 可执行段私有脏页
 *   int    nativeAnonExec()       — 无名可执行映射（代码岛）
 *   int    nativeTrampoline()     — ARM64 跳板扫描
 *   int    nativeLibcPrologue()   — libc 入口 内存 vs 磁盘
 *   int    nativeLoadPhase()      — 加载期(.init_array)检测相位
 *   int    nativeFridaDetect()    — 综合检测（评分阈值制，≥2 判检出）
 *   String nativeAnswer()         — 最终答案（加载期命中则永久锁定）
 *   String nativeStatus()         — 检测详情
 *
 * 关键创新：从「明文特征嗅探」进阶到「抓注入本身」——代码岛 + libc 完整性。
 */
public class h63Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL26 · 暮霭沉沉（★★★ 六路评分阈值制）\n\n"
                + "libdusk.so 导出十个函数：\n"
                + "  int    nativeTiming()\n"
                + "  int    nativeVersion()\n"
                + "  int    nativeSmapsDirty()\n"
                + "  int    nativeAnonExec()\n"
                + "  int    nativeTrampoline()\n"
                + "  int    nativeLibcPrologue()\n"
                + "  int    nativeLoadPhase()\n"
                + "  int    nativeFridaDetect()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "评分阈值制（6 路命中 ≥2 才判检出）：\n"
                + "  ①② 老路子：timing 侧信道 / 版本嗅探\n"
                + "  ③④⑤⑥ 抓注入本身：脏页 / 代码岛 / 跳板 / libc 完整性\n\n"
                + "★ 本关检测在 so【加载瞬间】(.init_array)就已执行并缓存，\n"
                + "  答案与加载期结果绑定——事后 hook 运行期检测解不开。\n\n"
                + "标记：两个标记一真一假，需仔细辨别");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        // 加载期相位：读这一行会触发 loadLibrary → .init_array 已跑完
        int phase = Sk.nativeLoadPhase();
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
                int result = Sk.nativeFridaDetect();
                if (result == 1) showFridaDetected();
                String status = Sk.nativeStatus();
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
                if (ans.isEmpty()) { Toast.makeText(h63Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                if (Sk.nativeFridaDetect() == 1) { showFridaDetected(); return; }
                String expected = Sk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(h63Activity.this, "FLAG_18_KL26{dusk_hides_the_truth}");
                    PassLog.mark(h63Activity.this, "KL26");
                } else {
                    Toast.makeText(h63Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(h63Activity.this)
                        .setTitle("提示")
                        .setMessage("六路评分阈值制（命中 ≥2 才判检出）：\n\n"
                                + "① timing 侧信道：多轮采样取中位数 + 多数超阈值\n"
                                + "② 版本/特征嗅探：运行时符号 + 映射里的 frida 特征\n"
                                + "③ 可执行段私有脏页：file-backed 代码段被写脏（COW）\n"
                                + "④ 无名可执行映射：没有 VMA 名的 r-x 段 = 可疑代码岛\n"
                                + "⑤ ARM64 跳板扫描：代码岛里成簇的 LDR X16/17,[PC] + BR\n"
                                + "⑥ libc 入口比对：关键函数入口 内存 vs 磁盘 是否一致\n\n"
                                + "③④⑤⑥ 是「抓注入本身」——洗掉特征串、hook 掉 libc 都躲不过。\n\n"
                                + "★ 时机：检测在 so【加载瞬间】(.init_array)已跑完并缓存，\n"
                                + "  进关点按钮只是查看结果。因此 hook nativeFridaDetect 返回 0 没用；\n"
                                + "  要么干净环境直接提交，要么 spawn 抢在 so 加载前替换检测。\n\n"
                                + "静态复刻：SEED = 20280720\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl26, 140));

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
