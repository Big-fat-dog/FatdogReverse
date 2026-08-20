package com.fatdog.reverse;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Shader;
import android.view.View;

// 圆形头像：方形位图转圆形绘制，无描边。
public class CircleAvatarView extends View {
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private Bitmap bitmap;

    public CircleAvatarView(Context c) {
        super(c);
    }

    public void setBitmap(Bitmap b) {
        bitmap = b;
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float cx = getWidth() / 2f;
        float cy = getHeight() / 2f;
        float r = Math.min(cx, cy);

        paint.setShader(null);
        if (bitmap != null && !bitmap.isRecycled()) {
            BitmapShader shader = new BitmapShader(bitmap, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
            Matrix m = new Matrix();
            float scale = r * 2 / Math.min(bitmap.getWidth(), bitmap.getHeight());
            m.setScale(scale, scale);
            m.postTranslate((getWidth() - bitmap.getWidth() * scale) / 2f,
                    (getHeight() - bitmap.getHeight() * scale) / 2f);
            shader.setLocalMatrix(m);
            paint.setShader(shader);
            canvas.drawCircle(cx, cy, r, paint);
        } else {
            paint.setColor(0xFFD9D9DE);
            canvas.drawCircle(cx, cy, r, paint);
        }
    }
}