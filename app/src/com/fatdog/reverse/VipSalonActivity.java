package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

// smali 关卡 1（对应教程 19）：一个普通的 VIP 检测。
// isVip() 恒返回 false，所以按钮永远走"拒绝"分支。
// 解题路线：apktool 解包 -> 打开 smali 里这个类的 isVip()，
//           把 return 的常量 0x0 改成 0x1（或把按钮回调里的 if-nez 跳转反过来）
//           -> 回编译 -> 重签名 -> 安装。
public class VipSalonActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("VIP 会员专属内容。现在你不是会员，点击只会被拒绝。让 App 认为你是 VIP，再进来查看会员内容。");
        box.addView(tv, Ui.wrap(8));

        Button btn = new Button(this);
        Ui.styleButton(btn);
        btn.setText("查看会员内容");
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (isVip()) {
                    Celebration.show(VipSalonActivity.this, "FLAG_18_L7{smali_vip_bypass}");
                    PassLog.mark(VipSalonActivity.this, "L7");
                } else {
                    Toast.makeText(VipSalonActivity.this,
                            "仅 VIP 会员可用。", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(VipSalonActivity.this)
                        .setTitle("提示")
                        .setMessage("用 apktool 解包，找到 isVip()。让它的返回值恒为 true，再回编译、重签名、安装。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_07));

        setContentView(box);
        ThemeKit.apply(this);
    }

    boolean isVip() {
        return false;
    }
}