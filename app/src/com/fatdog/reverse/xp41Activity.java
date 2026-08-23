package com.fatdog.reverse;


import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

public class xp41Activity extends Activity {

    private TextView status;
    private boolean passed = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("Xposed \u7b2c\u56db\u5173 \u00b7 \u65a9\u5173\u593a\u9698\n\n"
                + "\u672c\u9875\u6709\u4e09\u91cd\u6821\u9a8c\u94fe\uff1acheckA \u2192 checkB \u2192 checkC\u3002\n"
                + "\u5168\u90e8\u8fd4\u56de true \u624d\u80fd\u901a\u5173\u3002\n"
                + "\u63d0\u793a\uff1a\u7528 XC_MethodReplacement \u66ff\u6362 checkB \u4e3a\u6052\u771f\u5373\u53ef\u3002");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        status = new TextView(this);
        status.setText("\u68c0\u6d4b\u4e2d\u2026");
        status.setTextSize(16);
        status.setGravity(Gravity.CENTER);
        status.setPadding(0, Ui.dp(20), 0, Ui.dp(20));
        box.addView(status, Ui.wrap(4));

        setContentView(box);
        ThemeKit.apply(this);

        boolean a = TripleGate.checkA();
        boolean b = TripleGate.checkB();
        boolean c = TripleGate.checkC();
        if (a && b && c && !passed) {
            passed = true;
            status.setText("\u2713 \u4e09\u91cd\u6821\u9a8c\u5168\u90e8\u901a\u8fc7\uff01");
            Celebration.show(xp41Activity.this, "FLAG_18_L41{triple_gate_broken}");
            PassLog.mark(xp41Activity.this, "L41");
        }
    }
}
