package com.fatdog.reverse;

import android.app.Activity;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

// 关卡 20：万恶广告劫（smali）。
// 玩法：进去只有一个"点此领取 1 亿大礼包"按钮，点了就弹连环广告——
// × 前 5 秒不显示，显示了也会瞬移，还弹嘲讽 Toast，正常操作永远关不掉。
// 正解：apktool 反编译 -> AdBox.smali 的 <clinit> 把开关 `a` 从 1 改成 0
//      （或把 showAd 门口 sget a + if-nez 反转）-> 重打包重签名 -> 广告不再弹，
//      页面出现「我已关掉广告」-> 点击 -> 礼花 + flag。
// Frida 双解：Java.use('com.fatdog.reverse.AdBox').a.value = 0;
public class a20Activity extends Activity {

    private LinearLayout successBox;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ThemeKit.blockForceDark(this);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(Ui.dp(32), Ui.dp(40), Ui.dp(32), Ui.dp(40));

        TextView title = new TextView(this);
        title.setText("关卡 20：万恶广告劫");
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setGravity(Gravity.CENTER);
        box.addView(title, Ui.wrap(0));

        TextView tip = new TextView(this);
        tip.setText("这页只有 1 亿大礼包可以领。\n但领之前，你得先熬过这劫——\n提示：广告的开关在代码里，找到它关掉，就通关了。");
        tip.setTextSize(15);
        tip.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        tip.setGravity(Gravity.CENTER);
        box.addView(tip, Ui.wrap(10));

        Button claim = new Button(this);
        claim.setText(Sx.s(AdBox.C_CLAIM));
        claim.setTextSize(16);
        claim.setTypeface(Typeface.DEFAULT_BOLD);
        claim.setBackground(bg(0xFFFB7299));
        claim.setTextColor(0xFFFFFFFF);
        claim.setMinHeight(Ui.dp(56));
        box.addView(claim, Ui.wrap(24));
        claim.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (AdBox.adsOn()) {
                    AdBox.showAd(a20Activity.this);   // 连环广告：正常点永远关不掉
                } else {
                    onAdsGone(a20Activity.this);      // 开关已被关：直接放行
                }
            }
        });

        // 成功区：广告被关掉后才出现
        successBox = new LinearLayout(this);
        successBox.setOrientation(LinearLayout.VERTICAL);
        successBox.setGravity(Gravity.CENTER);
        TextView ok = new TextView(this);
        ok.setText("恭喜，广告心魔已除");
        ok.setTextSize(18);
        ok.setTextColor(0xFF67C23A);
        successBox.addView(ok, Ui.wrap(0));

        final Button done = new Button(this);
        done.setText(Sx.s(AdBox.C_DONE));
        done.setTextSize(16);
        done.setTypeface(Typeface.DEFAULT_BOLD);
        done.setBackground(bg(0xFF67C23A));
        done.setTextColor(0xFFFFFFFF);
        done.setMinHeight(Ui.dp(56));
        successBox.addView(done, Ui.wrap(16));
        done.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Celebration.show(a20Activity.this, "FLAG_18_L20{ads_are_gone}");
                PassLog.mark(a20Activity.this, "L20");
            }
        });
        successBox.setVisibility(View.GONE);
        box.addView(successBox, Ui.wrap(24));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }

    /** AdBox 检测到开关已关 / 玩家改码后：露出成功按钮。 */
    public static void onAdsGone(final Activity act) {
        if (act instanceof a20Activity) {
            act.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    a20Activity a = (a20Activity) act;
                    if (a.successBox != null) {
                        a.successBox.setVisibility(View.VISIBLE);
                    }
                }
            });
        }
    }

    private GradientDrawable bg(int color) {
        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.RECTANGLE);
        g.setCornerRadius(Ui.dp(14));
        g.setColor(color);
        return g;
    }
}