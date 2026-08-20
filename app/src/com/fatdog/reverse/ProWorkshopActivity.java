package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

// smali 关卡 3（对应教程 19）：最难的一关，多重资格 + 诱饵。
// checkStatus() = isVip() && isActivated()，两个都要过。
// 只改一个检查，会走进 else 分支——注意那里的字符串看起来很像 flag。
// 解题路线：apktool 解包，把 checkStatus() 的 smali 整体改成返回 true
//          （或把 isVip() 和 isActivated() 都改成返回 true）。
public class ProWorkshopActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("Pro 工坊，仅供已激活的高级会员。通过资格检查后进入工坊。");
        box.addView(tv, Ui.wrap(8));

        Button btn = new Button(this);
        Ui.styleButton(btn);
        btn.setText("进入工坊");
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (checkStatus()) {
                    Celebration.show(ProWorkshopActivity.this, "FLAG_18_L9{multi_gate_cleared}");
                    PassLog.mark(ProWorkshopActivity.this, "L9");
                } else {
                    Toast.makeText(ProWorkshopActivity.this, "FLAG_18_L9{single_gate_not_enough}", Toast.LENGTH_LONG).show();
                }
            }
        });
        box.addView(btn, Ui.wrap(22));

        Button hint = new Button(this);
        Ui.styleButton(hint);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(ProWorkshopActivity.this)
                        .setTitle("提示")
                        .setMessage("资格检查不止一个，只改一个会走进失败分支。注意失败分支里那条很像 flag 的字符串是诱饵。把 checkStatus 整体改成返回 true 是最快的路。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_09));

        setContentView(box);
        ThemeKit.apply(this);
    }

    boolean checkStatus() {
        return isVip() && isActivated();
    }

    private boolean isVip() {
        return getSharedPreferences("fatdemo", Context.MODE_PRIVATE)
                .getBoolean("vip", false);
    }

    private boolean isActivated() {
        return new File(getFilesDir(), "activated.lic").exists();
    }
}