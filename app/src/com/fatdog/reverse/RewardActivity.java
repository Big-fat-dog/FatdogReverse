package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
// 关卡 6：一个没有 UI 入口的 Activity。
// 玩法：它被声明为 exported，但没有大厅按钮。找到它并启动，就能看到 flag。
public class RewardActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setGravity(Gravity.CENTER);
        tv.setTextSize(20);
        tv.setText("你是怎么找到我的？\n\nFLAG_18_L6{exported_activity}");
        box.addView(tv, Ui.wrap(8));

        Button hint = new Button(this);
        Ui.styleButton(hint);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(RewardActivity.this)
                        .setTitle("提示")
                        .setMessage("AndroidManifest.xml 里声明了很多组件。找一个大厅里没有按钮、却 exported=\"true\" 的 Activity，用 adb 把它拉起来。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_06));

        setContentView(box);
        ThemeKit.apply(this);
        PassLog.mark(this, "L6");
    }
}
