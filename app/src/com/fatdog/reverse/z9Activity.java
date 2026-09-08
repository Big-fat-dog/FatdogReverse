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

import java.security.MessageDigest;

// Frida 关卡 5（对应教程 20）：三层链路 + 双输入，内容横跨多个真实类 + 三个诱饵类。
// license 链路：base64 解码 -> AES 解密(密钥 A，在 XBox) -> AES 解密(密钥 B，在 Mux)
//              -> 逐字节异或 0x5A -> 得到 16 字节的 "GRANTED_2026_OK!"。
// deviceId 的正确值拆成两段异或放在 PivotParts，MD5 只做指纹校验。
// 诱饵：AesKit / Md5Tools / KeyFactory 都有加密代码或假密钥，但没有任何调用者。
// 解法：静态——还原 XBox/Mux 的密钥与 PivotParts 的分片；
//       动态——Frida Hook Cipher.doFinal 和 MessageDigest 观察整条链。
public class z9Activity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(48, 24, 48, 48);

        TextView tv = new TextView(this);
        tv.setText("同时提供正确的 license 和 deviceId，通过三层链路校验后获得 flag。");
        box.addView(tv, Ui.wrap(8));

        final EditText lic = new EditText(this);
        lic.setHint("license");
        lic.setLayoutParams(Ui.fullWidth(22));
        box.addView(lic);

        final EditText dev = new EditText(this);
        dev.setHint("deviceId");
        dev.setLayoutParams(Ui.fullWidth(22));
        box.addView(dev);

        Button btn = new Button(this);
        Ui.styleButton(btn);
        btn.setText("验证");
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (verify(lic.getText().toString(), dev.getText().toString())) {
                    Celebration.show(z9Activity.this, "FLAG_18_L14{triple_layer_chain}");
                    PassLog.mark(z9Activity.this, "L14");
                } else {
                    Toast.makeText(z9Activity.this,
                            "校验失败。", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(z9Activity.this)
                        .setTitle("提示")
                        .setMessage("license 要过三层变换，两把密钥分散在 XBox/Mux；deviceId 的正确值在 PivotParts 里分片异或存放，别对着 MD5 猜。注意排除那些没人调用的类，别用里面的假密钥。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(12));

        box.addView(Ui.banner(this, R.drawable.level_14));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }

    boolean verify(String license, String deviceId) {
        try {
            XBox xBox = XBox.getInstance();
            Mux mux = Mux.getInstance();
            PivotParts pivot = PivotParts.getInstance();

            byte[] s1 = xBox.decryptA(license);
            String plain = mux.finish(s1);
            return "GRANTED_2026_OK!".equals(plain)
                    && md5Hex(deviceId).equals(pivot.fingerprint());
        } catch (Exception e) {
            return false;
        }
    }

    private String md5Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
