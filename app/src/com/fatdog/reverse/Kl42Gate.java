package com.fatdog.reverse;

import android.content.Context;
import android.content.SharedPreferences;

// L42 的 Hook 目标 + 持久化计数器。
// coldStartCheck() 默认 false——只有 Xposed 模块把它 Hook 成 true，"持久化 Hook 生效"才成立
// （这正是与 Frida 的分水岭：Frida 断线即失效，Xposed 冷启动照样生效）。
// ticks 存 SharedPreferences（跨进程存活）：自毁前 tick 一次、进程被杀重启后仍能读到 >0，
// 这才真正证明了「Hook 熬过了冷启动」，而不是只证明"点过按钮"。
public class Kl42Gate {
    private static final String PREFS = "fatdog_xp42";
    private static final String KEY_TICKS = "ticks";

    private Kl42Gate() {}

    // 冷启动检测：默认 false，需被模块 Hook 成 true
    public static boolean coldStartCheck() {
        return false;
    }

    // 自毁前记一次（落盘，跨进程）
    public static void tick(Context ctx) {
        SharedPreferences sp = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        sp.edit().putInt(KEY_TICKS, sp.getInt(KEY_TICKS, 0) + 1).apply();
    }

    public static int getTicks(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt(KEY_TICKS, 0);
    }
}
