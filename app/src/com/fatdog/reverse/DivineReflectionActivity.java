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
    public static final String[] LEVEL_IDS = {
            "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8",
            "L9", "L10", "L11", "L12", "L13", "L14", "L15", "L16",
            "L17", "L18", "L19", "L20", "L21", "L22", "L23", "L24", "L25", "L26", "L27", "L28", "L29", "L30", "L31", "L32", "L33", "L34", "L35", "L36", "L37",             "KL1", "KL2", "KL3", "KL4", "KL5", "KL6", "L38", "L39", "L40", "L41", "L42", "KL7", "KL8", "KL9", "KL10", "L43", "L44", "L45", "L46", "L47",             "KL11", "KL12", "KL13", "KL14", "KL15", "KL16", "KL17", "KL18", "KL19", "KL20", "KL21", "KL22"};
    private static final String[] NAMES = {
            "破妄神瞳", "观微心诀", "算尽天机", "溯源追魂",
            "地脉搜灵", "九遁身法", "移花接木", "解钥神指",
            "阴阳玄关", "万法归一", "契约心经", "破阵天光",
            "双龙出海", "三才归一", "隔空取物", "逆流断脉",
            "奇门暗渡", "双钥破天", "雾隐摘星", "广告心魔",
            "偷天换日", "拔钉破罩", "拨云见日", "李代桃僵", "玄功夺舍", "双符合璧", "万法归宗", "天地噤声", "匿迹遁形", "剑冢寻锋", "两界拈针", "万蛊不侵", "万劫金身", "一念归墟", "双匣藏锋", "洞玄辨纹", "雪崩千里", "叩山门", "掌雷针", "渡鸦引", "裂冰诀", "踏虚步", "寒渊取钥", "傀儡线", "偷天换玉", "摘星拿月", "断岳斩", "万剑归宗", "裂魂启匣", "渊眼洞明", "踏罡步斗", "日月合璧", "照妖镜", "偷天手", "移形步", "以签为钥", "幽冥卷",             "偷梁换柱", "移花接木", "声东击西", "偷天换日", "万法归宗", "破壳新生", "金蝉脱壳",
            "乾坤迷阵", "虚空造化", "破壁飞升", "枯叶听风", "落影寻痕"};
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
            "查表识君：S 盒认阵，等号串里有钥匙",
            "雪崩之谜：换血之 IV，乱流裹真章",
            "叩山门：unidbg 初试啼声",
            "掌雷针：动态注册一引即发",
            "渡鸦引：跨界取钥一线牵",
            "裂冰诀：假文件破冰面",
            "踏虚步：五法归一登绝顶", "寒渊取钥：Rcon 换血，冰封之钥自解其冻",
            "傀儡线：改返回值如提线傀儡",             "偷天换玉：篡改入参于无形",
            "摘星拿月：私有字段探囊可取", "断岳斩：方法体一换，三关齐破", "万剑归宗：自毁重生，Hook 犹在", "裂魂匣：排列表换位藏刀，标准 DES 失灵",
            "渊眼洞明：CK 尾部换血，标准 SM4 解不开的幽泉之眼",
            "踏罡步斗：KSA 换阵掩码覆流，标准 RC4 解不开的天罡北斗",
            "日月合璧：IV 换血填充前移叠 MixColumns 对调，双层皆魔改",
            "照妖镜：重签指纹必变，一照便知真假",
            "偷天手：摘要下沉 native 记账核账，换票方能过审",
            "移形步：自读 APK 剥证书，PM 全链失明",
            "以签为钥：证书 DER 派生 HMAC 密钥，L4 型主打",
            "幽冥合卷：收官综合卷，四重防线齐上阵",
            "偷梁换柱：SO patch 入门，nop 掉比较跳转指令",
            "移花接木：Frida hook 入门，一行替换返回值",
            "声东击西：CRC 自校验，patch 一处触发连锁",
            "偷天换日：三 so 交叉验证，patch 任一即全链失效",
            "万法归宗：收官综合卷，三阶段递进谜题",
            "破壳新生：一代壳 DEX 静态加密，XOR+旋转解密还原",
            "金蝉脱壳：二代壳 DEX 热加载+反调试，三重检测绕过",
            "乾坤迷阵：OLLVM 控制流平坦化，状态机真假 case 辨析",
            "虚空造化：VMP 虚拟机保护，寄存器式字节码逐指令翻译",
            "破壁飞升：三代壳综合收官，反调试+OLLVM+VMP 三层齐破",
            "枯叶听风：端口探测+D-Bus 协议指纹，双路 OR 静默捕获",
            "落影寻痕：fd 扫描+maps 搜索，frida 踪迹无处遁形"};
    private static final String[] CAT_NAMES = {
            "静态分析 · 观物之能", "Smali 挑战 · 篡改之道", "Frida Hook · 附身之术", "网络对抗 · 取数之法", "终极试炼 · 破阵之威", "Native 试炼 · 破壁之术", "Xposed 实战 · 御偶之术", "签名校验 · 缚妖之锁", "天地秘境 · 登天之路"};
    private static final int[] CAT_COLORS = {0xFF409EFF, 0xFF67C23A, 0xFFFB7299, 0xFFE6A23C, 0xFFB37FEB, 0xFF00BFA5, 0xFF7986CB, 0xFF20C9AC, 0xFFFF6D3B};
    private static final int[][] CAT_LEVELS = {
            {0, 1, 2, 3, 4, 5}, {6, 7, 8}, {9, 10, 11, 12, 13},             {14, 15, 16, 17, 18}, {19, 20, 21, 22, 23, 24, 25, 26}, {27, 28, 29, 30, 31, 32, 33, 34, 35, 36}, {43, 44, 45, 46, 47}, {52, 53, 54, 55, 56},             {37, 38, 39, 40, 41, 42, 48, 49, 50, 51, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68}};

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
