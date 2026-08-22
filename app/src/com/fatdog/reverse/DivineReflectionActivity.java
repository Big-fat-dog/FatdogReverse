package com.fatdog.reverse;

import android.app.Activity;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

// 神念自察：按 app 逆向的关卡类型对应功法，战胜关卡即"参悟"。
// buildReflectionView() 可作为内容嵌入个人主页的"神念自察"分类。
public class DivineReflectionActivity extends Activity {
    private static final String[] LEVEL_IDS = {
            "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8",
            "L9", "L10", "L11", "L12", "L13", "L14", "L15", "L16",
            "L17", "L18", "L19", "L20", "L21", "L22", "L23", "L24", "L25", "L26", "L27", "L28", "L29", "L30", "L31", "L32", "L33", "L34", "L35", "L36"};
    private static final String[] NAMES = {
            "破妄神瞳", "观微心诀", "算尽天机", "溯源追魂",
            "地脉搜灵", "九遁身法", "移花接木", "解钥神指",
            "阴阳玄关", "万法归一", "契约心经", "破阵天光",
            "双龙出海", "三才归一", "隔空取物", "逆流断脉",
            "奇门暗渡", "双钥破天", "雾隐摘星", "广告心魔",
            "偷天换日", "拔钉破罩", "拨云见日", "李代桃僵", "玄功夺舍", "双符合璧", "万法归宗", "缄默诀", "隐踪诀", "无名诀", "穿针诀", "定心诀", "金刚诀", "归墟诀", "双匣诀", "查表诀"};
    private static final String[] DESCS = {
            "明文藏宝：一眼看穿藏匿之处",
            "Base64 马甲：编码无处遁形",
            "拼图游戏：异或迷局一算即明",
            "MD5 验门：从 32 位摘要还原口令",
            "资源藏宝：在 assets 里挖出宝藏",
            "隐藏入口：寻得无人知晓的 Activity",
            "VIP 检测：改写 smali 让判定失效",
            "激活码：还原 fill-array-data 密文",
            "多重资格：识破诱饵，双关尽破",
            "SHA-256 验门：哈希被一击击穿",
            "HMAC 验签：签名形同虚设",
            "AES 秘库：密码库轰然洞开",
            "双重校验：账号令牌一穿而过",
            "三层链路：加密链尽数斩断",
            "千数求和：远程取数一念成和",
            "流密码暗河：双向 RC4 密流一斩即断",
            "玄门遁甲：国密 SM4/SM3 奇门暗渡",
            "乾坤密钥：公私双钥一掌破天",
            "雾里看花：混淆迷雾中摘星取数",
            "万恶广告劫：smali 改一个开关，心魔退散，广告再不打扰",
            "踏云寻踪：信任之锚偷天换日",
            "双锁封疆：证书双锁连根拔起",
            "白屏迷雾：证书放行云开雾散",
            "换票迷局：反 Hook 与内存换值",
            "灵台证真：native 门禁与 JNI 签名",
            "双符合璧：互验名帖，双向 TLS 通玄",
            "万法归宗：抓包明文仍需复刻签名",
            "缄默之钥：异或藏钥，strings 哑火",
            "隐姓埋名：动态注册无所遁形",
            "无名剑冢：指针表里认真身，UTF-16 密语现形",
            "两界穿针：跨层拼装，干扰包里辨真章",
            "心魔哨兵：四路检测静默投毒，定心破之",
            "金刚不坏：CRC 结界，三式皆可破",
            "万法归墟：三季合卷，三路皆通",
            "双匣暗渡：魔数认阵，真假匣中辨宝",
            "查表识君：S 盒认阵，等号串里有钥匙"};
    private static final String[] CAT_NAMES = {
            "静态分析 · 观物之能", "Smali 挑战 · 篡改之道", "Frida Hook · 附身之术", "网络对抗 · 取数之法", "终极试炼 · 破阵之威", "Native 试炼 · 破壁之术"};
    private static final int[] CAT_COLORS = {0xFF409EFF, 0xFF67C23A, 0xFFFB7299, 0xFFE6A23C, 0xFFB37FEB, 0xFF00BFA5};
    private static final int[][] CAT_LEVELS = {
            {0, 1, 2, 3, 4, 5}, {6, 7, 8}, {9, 10, 11, 12, 13},             {14, 15, 16, 17, 18}, {19, 20, 21, 22, 23, 24, 25, 26}, {27, 28, 29, 30, 31, 32, 33, 34, 35}};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        FrameLayout root = new FrameLayout(this);
        ImageView bg = new ImageView(this);
        bg.setImageResource(R.drawable.bg_profile);
        bg.setScaleType(ImageView.ScaleType.CENTER_CROP);
        bg.setAlpha(0.16f);
        root.addView(bg, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        root.addView(buildPage(this), new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        setContentView(root);
        ThemeKit.apply(this);
    }

    // 独立页面：返回头 + 功法列表
    private static View buildPage(final Activity act) {
        LinearLayout col = new LinearLayout(act);
        col.setOrientation(LinearLayout.VERTICAL);

        LinearLayout header = new LinearLayout(act);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(act, 8), dp(act, 16), dp(act, 16), dp(act, 8));
        TextView back = new TextView(act);
        back.setText("‹ 返回");
        back.setTextSize(16);
        back.setTextColor(0xFFFB7299);
        back.setPadding(dp(act, 12), dp(act, 4), dp(act, 12), dp(act, 4));
        back.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                act.finish();
            }
        });
        header.addView(back, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));
        TextView title = new TextView(act);
        title.setText("神念自察");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(0xFF409EFF);
        title.setGravity(Gravity.CENTER);
        header.addView(title, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        col.addView(header);

        col.addView(buildReflectionView(act), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT));
        return col;
    }

    // 可嵌入内容：功法列表，无页头
    static View buildReflectionView(final Activity act) {
        boolean dark = ThemeKit.isDark(act);
        ScrollView scroll = new ScrollView(act);
        LinearLayout list = new LinearLayout(act);
        list.setOrientation(LinearLayout.VERTICAL);
        list.setPadding(dp(act, 20), dp(act, 8), dp(act, 20), dp(act, 24));

        int got = 0;
        for (String id : LEVEL_IDS) {
            if (PassLog.isDone(act, id)) got++;
        }
        TextView summary = new TextView(act);
        summary.setText("已参悟功法 " + got + " / " + LEVEL_IDS.length + " 门");
        summary.setTextSize(14);
        summary.setTextColor(ThemeKit.muted(dark));
        summary.setGravity(Gravity.CENTER);
        list.addView(summary, Ui.fullWidth(2));

        for (int c = 0; c < CAT_LEVELS.length; c++) {
            list.addView(buildCategoryHeader(act, CAT_NAMES[c], CAT_COLORS[c]));
            for (int idx : CAT_LEVELS[c]) {
                list.addView(buildAchievement(act, idx, CAT_COLORS[c]));
            }
        }
        scroll.addView(list);
        return scroll;
    }

    private static View buildCategoryHeader(Activity act, String name, int color) {
        TextView tv = new TextView(act);
        tv.setText(name);
        tv.setTextSize(14);
        tv.setTypeface(Typeface.DEFAULT_BOLD);
        tv.setTextColor(color);
        LinearLayout.LayoutParams lp = Ui.wrap(12);
        lp.leftMargin = dp(act, 4);
        tv.setLayoutParams(lp);
        return tv;
    }

    private static View buildAchievement(Activity act, int idx, int accent) {
        boolean dark = ThemeKit.isDark(act);
        boolean done = PassLog.isDone(act, LEVEL_IDS[idx]);

        LinearLayout card = new LinearLayout(act);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setGravity(Gravity.CENTER_VERTICAL);
        card.setPadding(dp(act, 14), dp(act, 12), dp(act, 14), dp(act, 12));

        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.RECTANGLE);
        g.setCornerRadius(dp(act, 14));
        g.setColor(dark ? 0xFF1F1F26 : 0xFFFFFFFF);
        g.setStroke(dp(act, 1), done ? (accent & 0x55FFFFFF) : 0x22000000);
        card.setBackground(g);

        LinearLayout.LayoutParams lp = Ui.fullWidth();
        lp.topMargin = dp(act, 8);
        card.setLayoutParams(lp);

        ImageView icon = new ImageView(act);
        icon.setImageResource(R.drawable.ic_star);
        icon.setColorFilter(done ? accent : 0xFF4A4A52);
        card.addView(icon, new LinearLayout.LayoutParams(dp(act, 30), dp(act, 30)));

        LinearLayout info = new LinearLayout(act);
        info.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams infoLp = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        infoLp.leftMargin = dp(act, 12);
        card.addView(info, infoLp);

        TextView name = new TextView(act);
        name.setText((done ? "◆ " : "◇ ") + NAMES[idx] + " · " + LEVEL_IDS[idx]);
        name.setTextSize(15);
        name.setTypeface(Typeface.DEFAULT_BOLD);
        name.setTextColor(done ? ThemeKit.text(dark) : 0xFF6A6A72);
        info.addView(name);

        TextView desc = new TextView(act);
        desc.setText(done ? DESCS[idx] : "尚未参悟此门功法");
        desc.setTextSize(12);
        desc.setTextColor(done ? ThemeKit.muted(dark) : 0xFF5A5A62);
        info.addView(desc, Ui.wrap(2));

        TextView badge = new TextView(act);
        badge.setText(done ? "已悟" : "未悟");
        badge.setTextSize(11);
        badge.setTextColor(0xFFFFFFFF);
        badge.setPadding(dp(act, 10), dp(act, 3), dp(act, 10), dp(act, 3));
        badge.setGravity(Gravity.CENTER);
        GradientDrawable bg = new GradientDrawable();
        bg.setShape(GradientDrawable.RECTANGLE);
        bg.setCornerRadius(dp(act, 10));
        bg.setColor(done ? accent : 0xFF4A4A52);
        badge.setBackground(bg);
        card.addView(badge);
        return card;
    }

    private static int dp(Activity a, float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                a.getResources().getDisplayMetrics());
    }
}
