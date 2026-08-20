package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.InputStream;

// 关卡 5：flag 不在代码里，藏在 assets/config.json 的某个字段中。
// 玩法：在 APK 的资源里找出 flag，输入后提交；提示按钮只给方向，不给答案。
public class ConfigCenterActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("flag 根本不在代码里。把它找出来，输入后提交。");
        box.addView(tv, Ui.wrap(8));

        final EditText input = new EditText(this);
        input.setHint("flag");
        input.setLayoutParams(Ui.fullWidth(22));
        box.addView(input);

        Button submit = new Button(this);
        Ui.styleButton(submit);
        submit.setText("提交");
        submit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    if (readFlag().equals(input.getText().toString().trim())) {
                        Celebration.show(ConfigCenterActivity.this, readFlag());
                        PassLog.mark(ConfigCenterActivity.this, "L5");
                    } else {
                        Toast.makeText(ConfigCenterActivity.this, "不对，再找找。", Toast.LENGTH_SHORT).show();
                    }
                } catch (Exception e) {
                    Toast.makeText(ConfigCenterActivity.this, "读取失败: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(submit, Ui.wrap(22));

        Button hint = new Button(this);
        Ui.styleButton(hint);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(ConfigCenterActivity.this)
                        .setTitle("提示")
                        .setMessage("APK 本质就是一个 zip 压缩包。解压后看看 assets/ 目录里有什么。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_05));

        setContentView(box);
        ThemeKit.apply(this);
    }

    private String readAssets(String name) throws Exception {
        InputStream is = getAssets().open(name);
        byte[] buf = new byte[4096];
        int n = is.read(buf);
        is.close();
        return new String(buf, 0, n, "UTF-8");
    }

    private String readFlag() throws Exception {
        JSONObject cfg = new JSONObject(readAssets("config.json"));
        return cfg.getJSONObject("feature").getString("treasure_note");
    }
}
