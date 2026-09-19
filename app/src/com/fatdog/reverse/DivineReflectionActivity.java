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
            "L17", "L18", "L19", "L20", "L21", "L22", "L23", "L24", "L25", "L26", "L27", "L28", "L29", "L30", "L31", "L32", "L33", "L34", "L35", "L36", "L37",             "KL1", "KL2", "KL3", "KL4", "KL5", "KL6", "L38", "L39", "L40", "L41", "L42", "KL7", "KL8", "KL9", "KL10", "L43", "L44", "L45", "L46", "L47",             "KL11", "KL12", "KL13", "KL14", "KL15", "KL16", "KL17", "KL18", "KL19", "KL20", "KL21", "KL22", "KL23", "KL24", "KL25", "KL26", "KL27", "KL28", "KL29", "KL30", "KKL1", "KKL2", "KKL3",             "KKL4", "KKL5", "KL36", "KL37", "KL38", "KL39", "KL40", "KL41",             "L48", "L49", "L50", "L51", "L52", "L53", "KL42", "KL43", "KL44", "KL45", "KL46", "KL47", "KL48", "KL49", "KL50", "KL51", "KL52"};
    private static final String[] NAMES = {
            "破妄神瞳", "观微心诀", "算尽天机", "溯源追魂",
            "地脉搜灵", "九遁身法", "移花接木", "解钥神指",
            "阴阳玄关", "万法归一", "契约心经", "破阵天光",
            "双龙出海", "三才归一", "隔空取物", "逆流断脉",
            "奇门暗渡", "双钥破天", "雾隐摘星", "广告心魔",
            "偷天换日", "拔钉破罩", "拨云见日", "李代桃僵", "玄功夺舍", "双符合璧", "万法归宗", "天地噤声", "匿迹遁形", "剑冢寻锋", "两界拈针", "万蛊不侵", "万劫金身", "一念归墟", "双匣藏锋", "洞玄辨纹", "雪崩千里", "叩山门", "掌雷针", "渡鸦引", "裂冰诀", "踏虚步", "寒渊取钥", "傀儡线", "偷天换玉", "摘星拿月", "断岳斩", "万剑归宗", "裂魂启匣", "渊眼洞明", "踏罡步斗", "日月合璧", "照妖镜", "偷天手", "移形步", "以签为钥", "幽冥卷",             "偷梁换柱", "移花接木", "声东击西", "偷天换日", "万法归宗", "破壳新生", "金蝉脱壳",
            "乾坤迷阵", "虚空造化", "破壁飞升", "枯叶听风", "落影寻痕", "照妖显形", "冰鉴悬镜",          "暮雾锁听", "暮霭沉沉", "轻纱覆影", "雪落无痕", "暗流涌动", "天机织锦",             "玄冥渊", "万剑冢", "断魂谷", "锁妖塔","诛仙台", "云中锦书", "风中鸢尾", "雾里观花", "月下独酌", "星河倒影",             "浅滩拾贝", "迷雾森林", "幽暗深渊", "雷霆山巅",             "冰封雪域", "焚天火域", "落日平原", "沙中藏贝", "桥上听风", "暗流涌动", "深渊合璧", "落叶归根", "深根固蒂", "斩草除根", "盘根错节", "枯木逢春", "迷雾初开", "虚实相生"};
    private static final String[] DESCS = {
            "破妄神瞳：透视明文藏宝之处，一眼看穿",
            "观微心诀：解码无处遁形，马甲之下原形毕露",
            "算尽天机：异或迷局一算即明，拼图自现",
            "溯源追魂：从摘要残痕追溯口令本源",
            "地脉搜灵：深入资源地脉，宝藏无处遁形",
            "九遁身法：寻得隐匿入口，遁入无人之境",
            "移花接木：篡改判定之术，让禁制失效",
            "解钥神指：还原密文阵列，激活之钥手到擒来",
            "阴阳玄关：识破诱饵，双重禁制一关即破",
            "万法归一：散列之门被一击击穿",
            "契约心经：签名验证形同虚设",
            "破阵天光：密码库轰然洞开，秘藏尽现",
            "双龙出海：双重校验一穿而过",
            "三才归一：三层加密链尽数斩断",
            "隔空取物：远程取数一念成和",
            "逆流断脉：双龙出海，密流斩于一念之间",
            "奇门暗渡：国密阵法三道关，奇门暗渡皆可破",
            "乾坤密钥：公私双钥合乾坤，一掌破天",
            "雾里看花：混淆迷障遮望眼，雾里摘星需慧根",
            "万恶广告劫：心魔作祟扰清净，一令退散归本真",
            "踏云寻踪：信任之锚系天际，偷天换日过重关",
            "双锁封疆：双龙锁国门，连根拔起方通途",
            "白屏迷雾：雾锁千重障，放行方见天",
            "换票迷局：反制窥探之术，内存换值辨真假",
            "灵台证真：native 门禁守灵台，签名真伪一线间",
            "双符合璧：双符合璧验真身，通玄之路双向开",
            "万法归宗：明文虽现仍需印，复刻签名方归宗",
            "缄默之钥：异或藏锋隐真钥，strings 沉默不泄天机",
            "隐姓埋名：暗度陈仓隐注册，无踪无迹遁无形",
            "无名剑冢：指针深处藏真身，密语现形破剑冢",
            "两界穿针：跨层拼装辨虚实，干扰丛中取真章",
            "心魔哨兵：四路暗哨守重关，定心破之方可行",
            "金刚不坏：结界护身三重锁，三式皆破方通行",
            "万法归墟：三季合卷万法归，三路齐通见真如",
            "双匣暗渡：魔数识阵辨真假，匣中藏宝待缘人",
            "查表识君：阵法认阵需识阵，暗纹之中藏真钥",
            "雪崩之谜：换血移花乱真章，雪崩之下辨流源",
            "叩山门：初试啼声问山门，一叩即开入道途",
            "掌雷针：雷霆一引动乾坤，注册之门一掌开",
            "渡鸦引：跨界取钥一线牵，渡鸦引路过重关",
            "裂冰诀：假面破冰现真途，裂冰之下有通路",
            "踏虚步：五法合一登绝顶，踏虚而行至巅峰",
            "寒渊取钥：换血解冻自化开，冰封之钥待缘取",
            "傀儡线：提线木偶换真假，改返回值如掌中物",
            "偷天换玉：篡改入参于无形，偷天之术手中握",
            "摘星拿月：私有字段探囊取，摘星拿月掌中握",
            "断岳斩：方法体一换，三关齐破断岳开",
            "万剑归宗：自毁重生剑犹在，Hook 之术不可废",
            "裂魂匣：排列表换位藏刀锋，标准之法失灵光",
            "渊眼洞明：换血改阵掩真容，标准之法难窥幽泉",
            "踏罡步斗：换阵掩码覆真流，标准之法难破天罡",
            "日月合璧：IV 换血移花接木，双层皆魔改难辨",
            "照妖镜：重签指纹必变化，一照便知真与假",
            "偷天手：核账记账守重关，换票方能过天审",
            "移形步：自读 APK 剥伪装，全链失明过重关",
            "以签为钥：证书之中藏真钥，派生之路通玄关",
            "幽冥合卷：四重防线收官卷，万法归一见真如",
            "偷梁换柱：SO patch 入门试，nop 跳转虽简单，门禁不止一道关",
            "移花接木：替换返回如提线，真判定藏在更深处",
            "声东击西：自校验守代码全，patch 一处连锁动",
            "偷天换日：三关交叉验证，patch 一关另外两关翻脸",
            "万法归宗：三阶段递进谜题，逐个击破方归宗",
            "破壳新生：一代壳封印未解，还原密钥位置是关键",
            "金蝉脱壳：二代壳类抽取，抽空的内容要等跑起来才回填原处",
            "乾坤迷阵：二代壳方法抽取，抽空的指令要等还原点才逐条填回",
            "虚空造化：还原点外立哨兵，先让它失明才见得着填回的东西",
            "破壁飞升：三层封印叠加守，少破一层都过不去",
            "枯叶听风：双路暗哨静默守，不留痕迹捕踪影",
            "落影寻痕：全域搜索觅踪迹，调试之影无处遁",
            "照妖显形：三路印证缺一路，暴露之局不可免",
            "冰鉴悬镜：双重检查层层卡，进程反调如设关",
            "暮雾锁听：三路印证雾里针，雾中藏针辨虚实",
            "暮霭沉沉：双路择一通则行，时序嗅探辨真伪",
            "轻纱覆影：双术交叉暗藏机，轻纱之下有杀机",
            "雪落无痕：双重检测择一路，雪落有痕终难藏",
            "暗流涌动：双基准守暗流底，涌动之下必有迹",
            "天机织锦：编码请求加签验，抓包可得结构需自还原",
            "玄冥渊：虚表派发守重关，抽取不回填种子难开",
            "万剑冢：壳中壳埋宝深处，解密内存加载密钥藏宽码",
            "断魂谷：四路哨兵守签名，命中一路即投毒，服务拒绝",
            "锁妖塔：自校验加多点账，patch 一处另处翻脸",
            "诛仙台：入口深埋 native 层，虚拟复合签密钥标记生",
            "云中锦书：天外锦书压原生，快照池里寻印记",
            "风中鸢尾：署名尽抹循指令，两瓣相合方见真",
            "雾里观花：网络层里迷雾锁，穿透证书识真钥",
            "月下独酌：FFI 边界碎片藏，拼装密钥月光凉",
            "星河倒影：三锁连环收官卷，层层解开见真章",
            "浅滩拾贝：H5 壳中寻桥影，注入之点隐真钥",
            "迷雾森林：国密阵法三套设，派发不清路不通",
            "幽暗深渊：双算法联防守重关，虚表派发干扰二十余路",
            "雷霆山巅：三重签名跨链守，一环断裂全链崩",
            "冰封雪域：魔改密码深栈递，三 SO 协同缺不可",
            "焚天火域：魔改分组轮函数变，异常控制收官卷",
            "落日平原：分组密码入门试，魔数藏匿轮填是考点",
            "沙中藏贝：沙掩贝中藏密卷，乱码深处觅真钥",
            "桥上听风：桥上消息裹自签，分发表里辨玄机",
            "暗流涌动：两层暗锁锁密流，逆流破之方见底", "深渊合璧：众术汇流收官卷，双锁合璧破深渊", "落叶归根：七道信号探根基，尽数噤声方算净", "深根固蒂：问根问锁问来处，属性之内辨真身", "斩草除根：不落之根藏账本，隐姓仆从无处遁", "盘根错节：内核刻名藏深处，一纸证章辨真身", "枯木逢春：八道问询汇一纸，静默之下见真章", "迷雾初开：乱麻路上辨真伪，拨雾方见数归途", "虚实相生：影随真路难分辨，剔影方得真章"};
    private static final String[] CAT_NAMES = {
            "静态分析 · 观物之能", "Smali 挑战 · 篡改之道", "Frida Hook · 附身之术", "网络对抗 · 取数之法", "终极试炼 · 破阵之威", "Native 试炼 · 破壁之术", "Xposed 实战 · 御偶之术", "签名校验 · 缚妖之锁", "天地秘境 · 登天之路", "Native大陆 · 破壁之术"};
    private static final int[] CAT_COLORS = {0xFF409EFF, 0xFF67C23A, 0xFFFB7299, 0xFFE6A23C, 0xFFB37FEB, 0xFF00BFA5, 0xFF7986CB, 0xFF20C9AC, 0xFFFF6D3B, 0xFFFF8A65};
    private static final int[][] CAT_LEVELS = {
            {0, 1, 2, 3, 4, 5}, {6, 7, 8}, {9, 10, 11, 12, 13},             {14, 15, 16, 17, 18}, {19, 20, 21, 22, 23, 24, 25, 26}, {27, 28, 29, 30, 31, 32, 33, 34, 35, 36},             {43, 44, 45, 46, 47}, {52, 53, 54, 55, 56},             {37, 38, 39, 40, 41, 42, 48, 49, 50, 51, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104},
            {88, 89, 90, 91, 92, 93}};

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
