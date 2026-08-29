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
import android.widget.TextView;
import android.widget.Toast;

// 太玄之初 KL17 · 金蝉脱壳：二代壳 DEX 热加载 + 反调试。
// libk17.so 导出：nativeAntiDebug/nativeDecrypt/nativeSeed/nativeAnswer/nativeStatus
// 反调试三重检测 + 反hook，全部通过才能拿到正确答案。
// 玩家需：① 绕过反调试 → ② 分析解密逻辑 → ③ 算出答案提交。
public class z54Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL17 · 金蝉脱壳（★★）\n\n"
                + "libk17.so 导出五个函数：\n"
                + "  int    nativeAntiDebug()\n"
                + "  String nativeDecrypt()\n"
                + "  int    nativeSeed()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "反调试三重检测 + 反hook，全通过才出答案。");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        // 答案输入框
        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入答案（32位 hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        int p = Ui.dp(10);
        ansIn.setPadding(p, p, p, p);
        root.addView(ansIn, Ui.fullWidth(10));

        // 提交按钮
        Button subBtn = new Button(this);
        subBtn.setText("提交答案"); Ui.styleButton(subBtn);
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                int ok = Ek.nativeAntiDebug();
                if (ok != 1) {
                    Toast.makeText(z54Activity.this,
                            "反调试未通过，请先绕过检测。", Toast.LENGTH_SHORT).show();
                    return;
                }
                String ans = ansIn.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(z54Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Ek.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(z54Activity.this, "FLAG_18_KL17{hotpatch_defeated}");
                    PassLog.mark(z54Activity.this, "KL17");
                } else {
                    Toast.makeText(z54Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(z54Activity.this)
                        .setTitle("提示")
                        .setMessage("二代壳分析路线：\n\n"
                                + "① IDA 分析 libk17.so → 找 JNI_OnLoad 里的反调试调用；\n"
                                + "② 反调试三重：ptrace 占坑 + TracerPid 检测 + Frida 端口 27042；\n"
                                + "③ 反hook：mmap 映射函数头 + 定时比对。\n\n"
                                + "绕过路线：\n"
                                + "· Frida：spawn 抢跑 → hook ptrace/TracerPid/端口检测 → 强制返回正确值\n"
                                + "· patch：nop 掉三处检测调用 + nop mmap 比对\n"
                                + "· 静态：完整分析热加载流程 → 手动解密 patch.dex\n\n"
                                + "解密逻辑：XOR 还原 Base64 → 解码得明文 → 提取种子 → SHA-256 算答案。\n"
                                + "注意诱饵 Fatdog_unpacker（多 er），真标记 Fatdog_unpack。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        // banner
        root.addView(Ui.banner(this, R.drawable.level_kl17, 140));

        setContentView(root);
        ThemeKit.apply(this);
    }
}
