package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

/**
 * 幽冥海 KL15 · 万法归宗：三阶段递进谜题。
 *
 * libshale.so 暴露四个独立入口：nativeGuard / nativeComputeA / nativeComputeB /
 * nativeComputeC / nativeVerify。A→B→C 三段依赖，verify 同时比对三值。
 * nativeGuard 与 verify 前面叠了编译期烘焙的真实代码段 CRC：静态 patch
 * 窗口内指令会返回 -2；Frida 纯运行时 hook 不改字节，因此不受影响。
 */
public class kl15Activity extends Activity {

    private final EditText[] boxes = new EditText[3];
    private TextView status;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL15 · 万法归宗（★★★★★）\n\n"
                + "libshale 是三阶段递进谜题：\n"
                + "A → B(A) → C(A,B)，verify 同时校验三值。\n\n"
                + "单独 hook 任一段都凑不出最终值；\n"
                + "入口还叠了代码段完整性校验，先把它看穿再说。");
        tv.setGravity(Gravity.CENTER);
        tv.setTextColor(Color.WHITE);
        tv.setTextSize(15);
        root.addView(tv, Ui.wrap(6));

        String[] names = {"A（阶段种子）", "B（由 A 推导）", "C（由 A‖B 推导）"};
        String[] hints = {"computeA() 的十进制返回值", "computeB(A) 的十进制返回值", "computeC(A,B) 的十进制返回值"};
        for (int i = 0; i < 3; i++) {
            final TextView label = new TextView(this);
            label.setText(names[i]);
            label.setTextColor(Color.WHITE);
            label.setTextSize(14);
            label.setGravity(Gravity.LEFT);
            root.addView(label, Ui.fullWidth(12));

            EditText et = new EditText(this);
            et.setHint(hints[i]);
            et.setTextColor(Color.WHITE);
            et.setHintTextColor(0x99FFFFFF);
            et.setTypeface(android.graphics.Typeface.MONOSPACE);
            et.setBackgroundColor(0x33FFFFFF);
            int p = Ui.dp(10);
            et.setPadding(p, p, p, p);
            root.addView(et, Ui.fullWidth(8));
            boxes[i] = et;
        }

        status = new TextView(this);
        status.setText("");
        status.setGravity(Gravity.CENTER);
        status.setTextColor(0x99FFFFFF);
        status.setTextSize(13);
        root.addView(status, Ui.wrap(6));

        Button submit = new Button(this);
        submit.setText("提交三值");
        Ui.styleButton(submit);
        submit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int guard = Am.nativeGuard(0);
                if (guard == -2) {
                    status.setText("完整性校验失败：so 代码段被改动过。");
                    status.setTextColor(0xFFFF8A80);
                    return;
                }
                try {
                    int a = parse32(boxes[0].getText().toString().trim());
                    int bv = parse32(boxes[1].getText().toString().trim());
                    int c = parse32(boxes[2].getText().toString().trim());
                    int r = Am.nativeVerify(a, bv, c);
                    if (r == -2) {
                        status.setText("完整性校验失败：so 代码段被改动过。");
                        status.setTextColor(0xFFFF8A80);
                        return;
                    }
                    if (r == 1) {
                        Celebration.show(kl15Activity.this, "FLAG_18_KL15{all_methods_converge}");
                        PassLog.mark(kl15Activity.this, "KL15");
                    } else {
                        status.setText("三值未收敛，重新推导一遍。");
                        status.setTextColor(0xFFFFB74D);
                    }
                } catch (NumberFormatException e) {
                    Toast.makeText(kl15Activity.this, "请输入十进制整数（可接受 0~4294967295）", Toast.LENGTH_LONG).show();
                }
            }
        });
        root.addView(submit, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(kl15Activity.this)
                        .setTitle("提示")
                        .setMessage("A 是种子变换，B 用 CRC32 从 A 衍生，C 是 A‖B 的 SHA-256 截段。\n\n"
                                + "四个入口都导出了：静态跟踪 A→B→C 调用关系、复刻算法，"
                                + "或 Frida hook 三个 compute 的出口拿值对拍。\n\n"
                                + "nativeGuard/nativeVerify 前有真实代码段 CRC：直接 patch 窗口内指令会被拒；"
                                + "纯运行时 hook（不改 so 字节）不触发该校验。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        Button back = new Button(this);
        back.setText("返回");
        Ui.styleButton(back);
        back.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });
        root.addView(back, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl15, 150));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }

    private static int parse32(String s) throws NumberFormatException {
        if (s.length() == 0) {
            throw new NumberFormatException("empty");
        }
        long l = Long.parseLong(s);
        if (l < 0 || l > 0xFFFFFFFFL) {
            throw new NumberFormatException("range");
        }
        return (int) l;
    }
}
