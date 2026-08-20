package com.fatdog.reverse;

import android.app.Activity;
import android.app.Dialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.util.Random;

// 关卡 20：万恶广告劫 的广告机。
// 唯一的真开关就是下面这个字段：
//     public static int a = 1;
// 正解：apktool 反编译，在 AdBox.smali 的 <clinit> 里把 "const/4 v0, 0x1; sput v0, AdBox->a:I"
//       改成 0x0（或把 showAd 门口 sget a + if-nez 反转为 if-eqz），重打包重签名即可。
// Frida 双解：Java.use('com.fatdog.reverse.AdBox').a.value = 0;
// 这里一大堆数字都是异或 0x4D 的文案，jadx 里看着头疼，smali 里也只是 const 数组——
// 别浪费时间解文案，解开关才是正路。
public class AdBox {
    public static int a = 1;              // ← 唯一的真实开关（1 = 广告不停弹 / 0 = 广告消失）

    static int step = 0;                  // 连环广告页号（关了一个来下一个，永远关不完）

    static final int[] ADS = {R.drawable.ad_01, R.drawable.ad_02, R.drawable.ad_03,
            R.drawable.ad_04, R.drawable.ad_05};

    // --- 以下全是异或 0x4D 保存的文案 ---
    static final int[] T0 = {171, 204, 224, 168, 219, 209, 171, 207, 229, 171, 199, 240, 169, 245, 224, 168, 233, 234, 168, 232, 219, 162, 241, 204};
    static final int[] G0 = {168, 205, 223, 165, 227, 236, 171, 218, 251, 109, 126, 125, 109, 170, 234, 223, 165, 202, 231, 168, 199, 229, 164, 239, 203, 168, 194, 219, 162, 241, 193, 170, 207, 244, 109, 142, 218, 109, 168, 194, 226, 168, 200, 254, 164, 218, 224};
    static final int[] T1 = {171, 207, 229, 170, 215, 201, 171, 196, 198, 171, 209, 247, 171, 209, 196, 109, 126, 109, 169, 245, 231, 170, 218, 200, 171, 226, 223, 162, 241, 204};
    static final int[] G1 = {170, 207, 244, 168, 202, 246, 170, 230, 198, 168, 192, 254, 171, 210, 232, 171, 208, 205, 162, 241, 193, 168, 194, 231, 164, 209, 205, 109, 126, 109, 168, 197, 203, 164, 223, 210};
    static final int[] T2 = {171, 245, 245, 171, 197, 194, 169, 246, 238, 170, 246, 206, 169, 245, 199, 164, 218, 229, 162, 241, 193, 164, 212, 221, 171, 218, 251, 168, 192, 199, 169, 246, 250};
    static final int[] G2 = {170, 207, 244, 168, 202, 246, 170, 230, 198, 168, 202, 194, 109, 124, 125, 125, 109, 168, 200, 206};
    static final int[] T3 = {168, 214, 240, 164, 212, 200, 168, 233, 234, 170, 196, 193, 164, 212, 221, 171, 218, 251, 109, 125, 109, 168, 200, 206, 164, 239, 203};
    static final int[] G3 = {169, 246, 200, 168, 196, 228, 109, 126, 109, 169, 245, 231, 168, 221, 192, 164, 239, 208, 162, 241, 193, 171, 196, 198, 171, 200, 239, 171, 218, 237};
    static final int[] T4 = {171, 209, 205, 168, 221, 195, 169, 245, 205, 171, 208, 236, 168, 244, 242, 168, 220, 199, 168, 216, 235};
    static final int[] G4 = {170, 209, 198, 168, 227, 193, 168, 253, 252, 165, 206, 240, 168, 200, 246, 170, 198, 218, 162, 241, 197, 170, 209, 210, 162, 241, 196};
    static final int[] T5 = {168, 222, 197, 168, 222, 197, 168, 222, 197, 162, 241, 193, 165, 242, 213, 171, 209, 196, 169, 245, 205, 171, 208, 236, 162, 241, 204};
    static final int[] G5 = {171, 207, 229, 169, 246, 232, 169, 245, 247, 168, 200, 254, 168, 243, 218, 171, 195, 196, 162, 241, 210, 168, 233, 228, 170, 209, 210};
    static final int[] T6 = {170, 225, 225, 169, 245, 196, 171, 208, 236, 162, 241, 204, 171, 255, 236, 171, 206, 254, 168, 197, 253, 168, 221, 234};
    static final int[] G6 = {168, 244, 242, 168, 220, 199, 170, 216, 193, 171, 253, 245, 168, 199, 229, 171, 209, 247, 162, 241, 193, 168, 246, 247, 165, 227, 227, 170, 214, 249, 171, 195, 232, 171, 217, 244, 169, 246, 238, 170, 237, 204};
    static final int[] T7 = {170, 225, 225, 168, 214, 214, 171, 208, 236, 162, 241, 210, 169, 245, 192, 168, 226, 244, 162, 241, 193, 164, 206, 240, 168, 243, 231, 170, 195, 226, 169, 245, 205, 168, 209, 197, 169, 247, 203};
    static final int[] G7 = {171, 224, 238, 168, 245, 245, 169, 247, 247, 171, 218, 228, 168, 192, 245, 165, 240, 240, 169, 247, 203, 162, 241, 193, 169, 240, 237, 165, 242, 213, 168, 209, 229, 170, 224, 196, 168, 200, 254, 164, 218, 224, 162, 241, 210};
    static final int[][] TAUNTS = {
            {171, 196, 198, 168, 197, 230, 171, 199, 219, 162, 241, 193, 164, 228, 225, 169, 245, 199, 168, 253, 252, 168, 232, 240},
            {168, 244, 242, 168, 220, 199, 165, 242, 213, 171, 255, 236, 170, 209, 198, 168, 227, 193, 168, 220, 239},
            {171, 205, 232, 169, 246, 205, 169, 244, 197, 162, 241, 193, 165, 242, 213, 171, 209, 196, 169, 245, 198, 169, 245, 205, 171, 227, 248},
            {169, 240, 237, 165, 242, 212, 171, 196, 198, 164, 205, 210, 169, 245, 192, 165, 236, 193, 168, 216, 199},
            {170, 209, 198, 168, 227, 193, 168, 244, 242, 168, 220, 199, 168, 203, 192, 165, 248, 253, 168, 213, 214},
    };
    static final int[] C_CLAIM = {170, 207, 244, 171, 224, 233, 164, 239, 203, 168, 194, 219, 109, 124, 109, 169, 247, 242, 168, 233, 234, 170, 233, 241, 168, 193, 200};
    static final int[] C_DOSE = {170, 209, 198, 168, 227, 193, 168, 200, 254, 164, 218, 224};
    static final int[] C_SEC = {170, 234, 223, 168, 221, 195, 168, 194, 226, 168, 200, 254};
    static final int[] C_X = {142, 218};
    static final int[] C_DONE = {171, 197, 220, 168, 250, 255, 168, 200, 254, 171, 195, 196, 168, 244, 242, 168, 220, 199};

    private static final Random RND = new Random();

    /** 供关卡页判断：广告开着没（smali 里同样是一眼可见的 sget + if-nez）。 */
    public static boolean adsOn() {
        return a != 0;
    }

    /** 连环广告入口：switch(step) 状态机，关完一条来下一条，永远关不完。 */
    public static void showAd(final Activity act) {
        if (a == 0) {                 // ← 关键判断：sget a + if-eqz（改成 a 为 0 后直接走这里）
            gone(act);
            return;
        }
        switch (step) {
            case 0: new AdFlow(act, R.drawable.ad_01, T0, G0, false).start(); break;
            case 1: new AdFlow(act, R.drawable.ad_02, T1, G1, false).start(); break;
            case 2: new AdFlow(act, R.drawable.ad_03, T2, G2, false).start(); break;
            case 3: new AdFlow(act, R.drawable.ad_04, T3, G3, false).start(); break;
            case 4: new AdFlow(act, R.drawable.ad_05, T4, G4, true).start(); break;   // 最后一条：关闭键在左下角
            case 5: new AdFlow(act, R.drawable.ad_01, T5, G5, true).start(); break;   // 循环回第一条：照样瞬移
            case 6: new AdFlow(act, R.drawable.ad_02, T6, G6, true).start(); break;
            case 7: new AdFlow(act, R.drawable.ad_03, T7, G7, true).start(); break;
            default: new AdFlow(act, R.drawable.ad_04, T3, G3, true).start(); break;
        }
        step = (step + 1) % 8;   // 8 个连续 case 形成 packed-switch（改开关才能跳出循环）
    }

    /** 广告被关掉后：通知关卡页露出「我已关掉广告」按钮。 */
    static void gone(final Activity act) {
        act.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                a20Activity.onAdsGone(act);
            }
        });
    }

    // ================= 单条广告：图 + 文案 + 会瞬移的 × =================
    private static class AdFlow {
        final Activity act;
        final int imgRes;
        final String title, tag;
        final boolean last;
        final Dialog d;
        final Handler h = new Handler(Looper.getMainLooper());
        final FrameLayout content;
        final TextView closeX, dose, count;
        int taps = 0;
        int remain = 5;
        int corners = -1;
        final Runnable ticker;

        AdFlow(Activity act, int imgRes, int[] titleArr, int[] tagArr, boolean last) {
            this.act = act;
            this.imgRes = imgRes;
            this.title = Sx.s(titleArr);
            this.tag = Sx.s(tagArr);
            this.last = last;

            d = new Dialog(act, android.R.style.Theme_Black_NoTitleBar_Fullscreen);
            content = new FrameLayout(act);
            content.setBackgroundColor(0xE6000000);

            ImageView img = new ImageView(act);
            img.setImageResource(imgRes);
            img.setScaleType(ImageView.ScaleType.FIT_CENTER);
            img.setPadding(Ui.dp(28), Ui.dp(60), Ui.dp(28), Ui.dp(90));
            content.addView(img, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.MATCH_PARENT));

            LinearLayout textBox = new LinearLayout(act);
            textBox.setOrientation(LinearLayout.VERTICAL);
            textBox.setGravity(Gravity.CENTER_HORIZONTAL);
            textBox.setPadding(Ui.dp(24), 0, Ui.dp(24), Ui.dp(24));
            TextView tv = new TextView(act);
            tv.setText(title);
            tv.setTextSize(20);
            tv.setTypeface(Typeface.DEFAULT_BOLD);
            tv.setTextColor(Color.WHITE);
            textBox.addView(tv);
            TextView tg = new TextView(act);
            tg.setText(tag);
            tg.setTextSize(13);
            tg.setTextColor(0xFFCCCCCC);
            textBox.addView(tg, Ui.wrap(6));
            content.addView(textBox, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    Gravity.BOTTOM));

            // × 关闭按钮：前 5 秒不显示，显示后点击会瞬移
            closeX = new TextView(act);
            closeX.setText(Sx.s(C_X));
            closeX.setTextSize(26);
            closeX.setTextColor(Color.WHITE);
            closeX.setGravity(Gravity.CENTER);
            closeX.setPadding(Ui.dp(12), Ui.dp(8), Ui.dp(12), Ui.dp(8));
            closeX.setVisibility(View.INVISIBLE);
            closeX.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    taps++;
                    toast(Sx.s(TAUNTS[RND.nextInt(TAUNTS.length)]));
                    teleportX();
                    if (taps >= 3 && dose.getVisibility() != View.VISIBLE) {
                        dose.setVisibility(View.VISIBLE);
                    }
                }
            });
            content.addView(closeX, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    Gravity.TOP | Gravity.RIGHT));

            // 看完关闭 / 倒数
            dose = new TextView(act);
            dose.setText(Sx.s(C_DOSE));
            dose.setTextSize(16);
            dose.setTypeface(Typeface.DEFAULT_BOLD);
            dose.setTextColor(0xFFFFFFFF);
            dose.setBackground(bg(0xFFFB7299, false));
            dose.setPadding(Ui.dp(18), Ui.dp(10), Ui.dp(18), Ui.dp(10));
            dose.setVisibility(View.GONE);
            dose.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    h.removeCallbacksAndMessages(null);
                    d.dismiss();
                    showAd(act);          // 关完再看下一条 → 连环，永远关不完
                }
            });
            content.addView(dose, doseLp());

            count = new TextView(act);
            count.setTextSize(14);
            count.setTextColor(0x99FFFFFF);
            content.addView(count, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    Gravity.TOP | Gravity.LEFT));

            d.setContentView(content);

            ticker = new Runnable() {
                @Override
                public void run() {
                    if (remain <= 0) {
                        count.setText("");
                        closeX.setVisibility(View.VISIBLE);   // 5 秒到，× 终于现身
                        return;
                    }
                    count.setText(Sx.s(C_SEC) + " " + remain);
                    remain--;
                    h.postDelayed(this, 1000);
                }
            };
        }

        void start() {
            d.show();
            h.postDelayed(ticker, 1000);
        }

        private void toast(String s) {
            Toast.makeText(act, s, Toast.LENGTH_SHORT).show();
        }

        private GradientDrawable bg(int color, boolean stroke) {
            GradientDrawable g = new GradientDrawable();
            g.setShape(GradientDrawable.RECTANGLE);
            g.setCornerRadius(Ui.dp(22));
            g.setColor(color);
            if (stroke) g.setStroke(Ui.dp(2), 0x44FFFFFF);
            return g;
        }

        private FrameLayout.LayoutParams doseLp() {
            FrameLayout.LayoutParams lp;
            if (last) {
                lp = new FrameLayout.LayoutParams(
                        FrameLayout.LayoutParams.WRAP_CONTENT,
                        FrameLayout.LayoutParams.WRAP_CONTENT,
                        Gravity.BOTTOM | Gravity.LEFT);        // 最后一条：关闭键在左下角
                lp.leftMargin = Ui.dp(28);
                lp.bottomMargin = Ui.dp(28);
            } else {
                lp = new FrameLayout.LayoutParams(
                        FrameLayout.LayoutParams.WRAP_CONTENT,
                        FrameLayout.LayoutParams.WRAP_CONTENT,
                        Gravity.BOTTOM | Gravity.RIGHT);        // 其余：右下角
                lp.rightMargin = Ui.dp(28);
                lp.bottomMargin = Ui.dp(28);
            }
            return lp;
        }

        private void teleportX() {
            int c;
            do {
                c = RND.nextInt(4);
            } while (c == corners);
            corners = c;
            int g;
            switch (c) {
                case 0: g = Gravity.TOP | Gravity.LEFT; break;
                case 1: g = Gravity.TOP | Gravity.RIGHT; break;
                case 2: g = Gravity.BOTTOM | Gravity.LEFT; break;
                default: g = Gravity.BOTTOM | Gravity.RIGHT; break;
            }
            FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT, g);
            lp.leftMargin = Ui.dp(10);
            lp.topMargin = Ui.dp(10);
            lp.rightMargin = Ui.dp(10);
            lp.bottomMargin = Ui.dp(10);
            closeX.setLayoutParams(lp);
            closeX.setVisibility(View.VISIBLE);
        }
    }
}