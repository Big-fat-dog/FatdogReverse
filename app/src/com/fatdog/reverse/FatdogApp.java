package com.fatdog.reverse;

import android.app.Application;

/**
 * 应用入口：进程创建时先触发一次原生库装载，之后各关卡直接调用即可。
 */
public class FatdogApp extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        AppInit.load();
    }
}
