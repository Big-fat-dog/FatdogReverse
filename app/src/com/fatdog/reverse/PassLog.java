package com.fatdog.reverse;

import android.content.Context;
import android.content.SharedPreferences;

// 通关进度记录：每个关卡触发 flag 时调 mark()，个人主页读 count() 算境界。
// 与任何加密/校验逻辑无关，纯粹是进度存储。
public class PassLog {
    private static final String PREFS = "fatdemo_progress";
    private static final String KEY_DONE = "done";
    private static final String KEY_COUNT = "count";

    public static void mark(Context ctx, String level) {
        SharedPreferences sp = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String token = ";" + level + ";";
        if (sp.getString(KEY_DONE, "").contains(token)) {
            return;   // 同一关只记一次
        }
        sp.edit()
                .putString(KEY_DONE, sp.getString(KEY_DONE, "") + token)
                .putInt(KEY_COUNT, sp.getInt(KEY_COUNT, 0) + 1)
                .apply();
    }

    public static int count(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getInt(KEY_COUNT, 0);
    }

    // 某一关是否已通关（太古禁地解锁、成就展示用）
    public static boolean isDone(Context ctx, String level) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(KEY_DONE, "").contains(";" + level + ";");
    }
}