package com.fatdog.reverse;

import android.annotation.SuppressLint;
import android.app.Dialog;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Movie;
import android.graphics.Paint;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.Window;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.InputStream;
import java.util.Random;

// 通关庆祝弹窗：播放庆祝 GIF + 生日礼花粒子 + "恭喜通关"，flag 一并显示；点击任意处关闭。
public class Celebration {

    public static void show(final Context ctx, final String flag) {
        final Dialog d = new Dialog(ctx);
        d.requestWindowFeature(Window.FEATURE_NO_TITLE);
        Window w = d.getWindow();
        if (w != null) w.setBackgroundDrawableResource(android.R.color.transparent);

        FrameLayout root = new FrameLayout(ctx);
        root.setPadding(Ui.dp(24), Ui.dp(24), Ui.dp(24), Ui.dp(24));

        // 背景圆角卡片
        android.graphics.drawable.GradientDrawable card = new android.graphics.drawable.GradientDrawable();
        card.setShape(android.graphics.drawable.GradientDrawable.RECTANGLE);
        card.setCornerRadius(Ui.dp(24));
        card.setColor(ThemeKit.isDark(ctx) ? 0xF226262D : 0xFFF7F7FB);
        card.setStroke(Ui.dp(2), 0xFFFB7299);
        root.setBackground(card);

        LinearLayout box = new LinearLayout(ctx);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(16), Ui.dp(16), Ui.dp(16));

        TextView title = new TextView(ctx);
        title.setText("🎉 恭喜通关 🎉");
        title.setTextSize(24);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setTextColor(0xFFFB7299);
        box.addView(title);

        // GIF + 礼花合成视图
        final CelebrateView cv = new CelebrateView(ctx);
        box.addView(cv, new LinearLayout.LayoutParams(Ui.dp(220), Ui.dp(220)));

        TextView flagTv = new TextView(ctx);
        flagTv.setText(flag);
        flagTv.setTextSize(15);
        flagTv.setTextColor(ThemeKit.text(ThemeKit.isDark(ctx)));
        flagTv.setGravity(Gravity.CENTER);
        box.addView(flagTv, Ui.wrap(12));

        TextView hint = new TextView(ctx);
        hint.setText("点击任意处关闭");
        hint.setTextSize(12);
        hint.setTextColor(ThemeKit.muted(ThemeKit.isDark(ctx)));
        box.addView(hint, Ui.wrap(8));

        root.addView(box, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER));

        // 点击任意处关闭（含 GIF/礼花区域）
        root.setOnTouchListener(new View.OnTouchListener() {
            @SuppressLint("ClickableViewAccessibility")
            @Override
            public boolean onTouch(View v, MotionEvent event) {
                if (event.getAction() == MotionEvent.ACTION_UP) {
                    cv.stop();
                    d.dismiss();
                }
                return true;
            }
        });

        d.setContentView(root);
        d.setCanceledOnTouchOutside(true);
        d.show();
        cv.start();
    }

    // 合成视图：播放 GIF + 礼花粒子
    private static class CelebrateView extends View {
        private Movie movie;
        private long movieStart = -1;
        private boolean playing = false;

        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Random rnd = new Random();
        private final float[] px, py, pv, pvr, pr, rot;
        private final int[] pcol;
        private long last = 0;

        CelebrateView(Context c) {
            super(c);
            try {
                InputStream is = c.getAssets().open("celebration.gif");
                movie = Movie.decodeStream(is);
                is.close();
            } catch (Exception ignored) {
            }
            int n = 90;
            px = new float[n]; py = new float[n]; pv = new float[n];
            pvr = new float[n]; pr = new float[n]; rot = new float[n]; pcol = new int[n];
            for (int i = 0; i < n; i++) reset(i);
        }

        private void reset(int i) {
            px[i] = rnd.nextInt(getWidth() > 0 ? getWidth() : 220);
            py[i] = -rnd.nextInt(80);
            pv[i] = 2 + rnd.nextFloat() * 4;
            pvr[i] = (rnd.nextFloat() - 0.5f) * 6;
            pr[i] = 4 + rnd.nextFloat() * 7;
            rot[i] = rnd.nextFloat() * 360;
            pcol[i] = Color.rgb(220 + rnd.nextInt(36), 120 + rnd.nextInt(120), 120 + rnd.nextInt(120));
        }

        void start() {
            movieStart = SystemClock.uptimeMillis();
            playing = true;
            last = SystemClock.uptimeMillis();
            invalidate();
        }

        void stop() {
            playing = false;
        }

        @Override
        protected void onDraw(Canvas canvas) {
            long now = SystemClock.uptimeMillis();
            float dt = (now - last) / 16f;
            last = now;

            // 礼花粒子下落
            if (playing) {
                for (int i = 0; i < px.length; i++) {
                    py[i] += pv[i] * dt;
                    px[i] += pvr[i] * dt;
                    rot[i] += 8 * dt;
                    if (py[i] > getHeight() + 20) reset(i);
                    paint.setColor(pcol[i]);
                    canvas.save();
                    canvas.rotate(rot[i], px[i], py[i]);
                    canvas.drawRect(px[i] - pr[i], py[i] - pr[i] / 2, px[i] + pr[i], py[i] + pr[i] / 2, paint);
                    canvas.restore();
                }
            }

            // GIF
            if (movie != null && playing) {
                int dur = movie.duration();
                if (dur <= 0) dur = 1000;
                int t = (int) ((now - movieStart) % dur);
                movie.setTime(t);
                int w = getWidth(), h = getHeight();
                float mw = movie.width(), mh = movie.height();
                float s = Math.min(w / mw, h / mh);
                float dx = (w - mw * s) / 2f, dy = (h - mh * s) / 2f;
                canvas.save();
                canvas.scale(s, s);
                canvas.translate(dx / s, dy / s);
                movie.draw(canvas, 0, 0);
                canvas.restore();
            }

            if (playing) {
                postInvalidateOnAnimation();
            }
        }
    }
}