package com.fatdog.reverse;

import android.app.Activity;
import android.app.Dialog;
import android.graphics.drawable.ColorDrawable;
import android.view.Window;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.ScrollView;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;

// 大厅：全屏内容区 + 右上角昼夜切换 + 底部导航三个页签（模仿 bilibili）。
// 基本关卡 = 顶部可横向滑动的分类条 + 按分类过滤的关卡列表；
// 天地秘境 = 高阶关卡分区；个人主页 = 修仙境界。
public class MainActivity extends Activity {
    private static final int ACTIVE_COLOR = 0xFFFB7299;   // bilibili 粉
    private static final int REQ_AVATAR = 1001;

    private static final String[] CATS = {"静态分析", "Smali 挑战", "Frida Hook（Java 层）", "Xposed 实战", "网络对抗", "SSL 抓包", "Native 试炼", "签名校验对抗"};
    private static final int[][] CAT_IDS = {
            {R.id.btn_vault, R.id.btn_note, R.id.btn_puzzle, R.id.btn_gate, R.id.btn_config},
            {R.id.btn_vip, R.id.btn_activate, R.id.btn_pro, R.id.btn_ad20},
            {R.id.btn_h10, R.id.btn_h11, R.id.btn_aes12, R.id.btn_dual13, R.id.btn_chain14},
            {R.id.btn_x38, R.id.btn_x39, R.id.btn_x40, R.id.btn_x41, R.id.btn_x42},
            {R.id.btn_pages15, R.id.btn_rc16, R.id.btn_f17, R.id.btn_r18, R.id.btn_l19},
            {R.id.btn_t21, R.id.btn_p22, R.id.btn_w23, R.id.btn_g24, R.id.btn_n25, R.id.btn_m26, R.id.btn_f27},
            {R.id.btn_l28, R.id.btn_l29, R.id.btn_l30, R.id.btn_l31, R.id.btn_l32, R.id.btn_l33, R.id.btn_l34, R.id.btn_l35, R.id.btn_l36, R.id.btn_l37},
            {R.id.btn_l43, R.id.btn_l44, R.id.btn_l45, R.id.btn_l46, R.id.btn_l47},
    };

    private FrameLayout host;
    private View levelsPage, kunlunPage, profilePage;

    private View tabLevels, tabKunlun, tabProfile;
    private ImageView imgLevels, imgKunlun, imgProfile;
    private TextView labelLevels, labelKunlun, labelProfile;
    private View bottomNav;
    private boolean kunlunOpen = false;
    private int kunlunCat = 0;

    private final ArrayList<TextView> chips = new ArrayList<TextView>();
    private TextView tipHidden;
    private int currentTab = 0;
    private int currentCat = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        host = findViewById(R.id.content_host);

        levelsPage = getLayoutInflater().inflate(R.layout.view_levels, host, false);
        host.addView(levelsPage);
        bindLevelButtons();
        setupCategories();

        kunlunPage = getLayoutInflater().inflate(R.layout.view_kunlun, host, false);
        host.addView(kunlunPage);

        profilePage = ProfileActivity.buildView(this, avatarClick, themeToggleDone);
        host.addView(profilePage);

        tabLevels = findViewById(R.id.tab_levels);
        tabKunlun = findViewById(R.id.tab_kunlun);
        tabProfile = findViewById(R.id.tab_profile);
        imgLevels = findViewById(R.id.img_levels);
        imgKunlun = findViewById(R.id.img_kunlun);
        imgProfile = findViewById(R.id.img_profile);
        labelLevels = findViewById(R.id.label_levels);
        labelKunlun = findViewById(R.id.label_kunlun);
        labelProfile = findViewById(R.id.label_profile);
        bottomNav = findViewById(R.id.bottom_nav);

        tabLevels.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                selectTab(0);
            }
        });
        tabKunlun.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (tryEnterKunlun()) selectTab(1);
            }
        });
        tabProfile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                selectTab(2);
            }
        });

        // 主题：默认黑夜；切换按钮在个人主页右上角，切换只动背景
        ThemeKit.apply(this);
        applyThemeExtras();

        selectTab(0);
    }

    // 仅主题相关的附加色（底部导航背景等），不改变任何"选框/卡片"配色
    private void applyThemeExtras() {
        boolean dark = ThemeKit.isDark(this);
        bottomNav.setBackgroundColor(dark ? 0xFF1C1C23 : 0xFFFFFFFF);
    }

    // 个人主页里点昼夜按钮后的收尾：其余页面随新主题刷新
    private final Runnable themeToggleDone = new Runnable() {
        @Override
        public void run() {
            applyThemeExtras();
            styleKunlun();
            selectCategory(currentCat);
            selectTab(currentTab);
        }
    };

    // 天地秘境页面的品牌色标题在主题上色后补回来
    private void styleKunlun() {
        boolean dark = ThemeKit.isDark(this);
        ((TextView) findViewById(R.id.kunlun_title)).setTextColor(0xFFFB7299);
        ((TextView) findViewById(R.id.kunlun_waiting)).setTextColor(ThemeKit.muted(dark));
    }

    private final View.OnClickListener avatarClick = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            Intent i = new Intent(Intent.ACTION_GET_CONTENT);
            i.setType("image/*");
            startActivityForResult(i, REQ_AVATAR);
        }
    };

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQ_AVATAR && resultCode == RESULT_OK && data != null && data.getData() != null) {
            try {
                InputStream is = getContentResolver().openInputStream(data.getData());
                FileOutputStream fos = openFileOutput("avatar.jpg", MODE_PRIVATE);
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) fos.write(buf, 0, n);
                fos.close();
                is.close();
                // 重新进入个人主页页签以刷新头像
                selectTab(2);
            } catch (Exception e) {
                Toast.makeText(this, "头像保存失败: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    private void selectTab(int index) {
        currentTab = index;
        levelsPage.setVisibility(index == 0 ? View.VISIBLE : View.GONE);
        if (index == 1 && kunlunOpen) {
            host.removeView(kunlunPage);
            kunlunPage = buildKunlunList();
            host.addView(kunlunPage);
        }
        if (index == 2) {
            // 每次进入个人主页都重新构建，保证通关数与头像最新
            host.removeView(profilePage);
            profilePage = ProfileActivity.buildView(this, avatarClick, themeToggleDone);
            host.addView(profilePage);
            profilePage.setVisibility(View.VISIBLE);
        } else {
            profilePage.setVisibility(View.GONE);
        }
        kunlunPage.setVisibility(index == 1 ? View.VISIBLE : View.GONE);

        setTabState(tabLevels, imgLevels, labelLevels, index == 0);
        setTabState(tabKunlun, imgKunlun, labelKunlun, index == 1);
        setTabState(tabProfile, imgProfile, labelProfile, index == 2);
    }

    private void setTabState(View tab, ImageView img, TextView label, boolean selected) {
        boolean dark = ThemeKit.isDark(this);
        img.setColorFilter(selected ? ACTIVE_COLOR : ThemeKit.muted(dark));
        label.setTextColor(selected ? ACTIVE_COLOR : ThemeKit.muted(dark));
        tab.setSelected(selected);
    }

    // ===== 关卡分类（横向滑动，类似 bilibili 分区条） =====

    private void setupCategories() {
        LinearLayout catBar = (LinearLayout) levelsPage.findViewById(R.id.cat_bar);
        tipHidden = (TextView) levelsPage.findViewById(R.id.tip_hidden);
        for (int i = 0; i < CATS.length; i++) {
            final int idx = i;
            TextView chip = new TextView(this);
            chip.setText(CATS[i]);
            chip.setTextSize(14);
            chip.setGravity(Gravity.CENTER);
            chip.setPadding(dp(14), dp(6), dp(14), dp(6));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            lp.rightMargin = dp(8);
            catBar.addView(chip, lp);
            chip.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    selectCategory(idx);
                }
            });
            chips.add(chip);
        }
        selectCategory(0);
    }

    private void selectCategory(int idx) {
        currentCat = idx;
        boolean dark = ThemeKit.isDark(this);
        for (int i = 0; i < chips.size(); i++) {
            boolean selected = (i == idx);
            GradientDrawable g = new GradientDrawable();
            g.setShape(GradientDrawable.RECTANGLE);
            g.setCornerRadius(dp(14));
            g.setColor(selected ? ACTIVE_COLOR : (dark ? 0xFF2A2A33 : 0xFFF1F1F4));
            chips.get(i).setBackground(g);
            chips.get(i).setTextColor(selected ? Color.WHITE : (dark ? 0xFFD8D8E0 : 0xFF3A3A42));
        }
        for (int i = 0; i < CAT_IDS.length; i++) {
            for (int id : CAT_IDS[i]) {
                levelsPage.findViewById(id).setVisibility(
                        i == idx ? View.VISIBLE : View.GONE);
            }
        }
        tipHidden.setVisibility(idx == 0 ? View.VISIBLE : View.GONE);
    }

    private void bindLevelButtons() {
        // 关卡 6 没有按钮（去 Manifest 里找）；关卡 20 是万恶广告劫（smali 改开关，按钮在 L19 与 L21 之间）
        bind(R.id.btn_vault, TokenVaultActivity.class);
        bind(R.id.btn_note, NoteKeeperActivity.class);
        bind(R.id.btn_puzzle, PuzzleBoxActivity.class);
        bind(R.id.btn_gate, GateKeeperActivity.class);
        bind(R.id.btn_config, ConfigCenterActivity.class);
        bind(R.id.btn_vip, VipSalonActivity.class);
        bind(R.id.btn_activate, ActivationRoomActivity.class);
        bind(R.id.btn_pro, ProWorkshopActivity.class);
        bind(R.id.btn_h10, HashCheckActivity.class);
        bind(R.id.btn_h11, MsgAuthActivity.class);
        bind(R.id.btn_aes12, b1Activity.class);
        bind(R.id.btn_dual13, k4Activity.class);
        bind(R.id.btn_chain14, z9Activity.class);
        bind(R.id.btn_x38, xp38Activity.class);
        bind(R.id.btn_x39, xp39Activity.class);
        bind(R.id.btn_x40, xp40Activity.class);
        bind(R.id.btn_x41, xp41Activity.class);
        bind(R.id.btn_x42, xp42Activity.class);
        bind(R.id.btn_pages15, s5Activity.class);
        bind(R.id.btn_rc16, t6Activity.class);
        bind(R.id.btn_f17, u7Activity.class);
        bind(R.id.btn_r18, v8Activity.class);
        bind(R.id.btn_l19, v9Activity.class);
        bind(R.id.btn_ad20, a20Activity.class);
        bind(R.id.btn_t21, w1Activity.class);
        bind(R.id.btn_p22, x2Activity.class);
        bind(R.id.btn_w23, y3Activity.class);
        bind(R.id.btn_g24, z24Activity.class);
        bind(R.id.btn_n25, a25Activity.class);
        bind(R.id.btn_m26, b26Activity.class);
        bind(R.id.btn_f27, c27Activity.class);
        bind(R.id.btn_l28, d28Activity.class);
        bind(R.id.btn_l29, e29Activity.class);
        bind(R.id.btn_l30, f30Activity.class);
        bind(R.id.btn_l31, g31Activity.class);
        bind(R.id.btn_l32, h32Activity.class);
        bind(R.id.btn_l33, i33Activity.class);
        bind(R.id.btn_l34, j34Activity.class);
        bind(R.id.btn_l35, k35Activity.class);
        bind(R.id.btn_l36, l36Activity.class);
        bind(R.id.btn_l37, m37Activity.class);
        bind(R.id.btn_l43, s43Activity.class);
        bind(R.id.btn_l44, t44Activity.class);
        bind(R.id.btn_l45, u45Activity.class);
        bind(R.id.btn_l46, v51Activity.class);
        bind(R.id.btn_l47, w52Activity.class);
    }

    private void bind(int id, final Class<?> target) {
        View button = levelsPage.findViewById(id);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, target));
            }
        });
    }

    // ================= 天地秘境（KL 独立编号，不计入境界） =================

    private boolean tryEnterKunlun() {
        if (!kunlunOpen && passDoneCount() >= 40) kunlunOpen = true;
        if (kunlunOpen) return true;
        showGateDialog();
        return false;
    }

    /* 主题化门禁弹窗：暗色圆角卡片 + 自绘按钮（替代纯白系统框） */
    private void showGateDialog() {
        boolean dark = ThemeKit.isDark(this);
        final Dialog dlg = new Dialog(this);
        dlg.requestWindowFeature(Window.FEATURE_NO_TITLE);

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(Ui.dp(22), Ui.dp(20), Ui.dp(22), Ui.dp(16));
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(Ui.dp(18));
        bg.setColor(dark ? 0xF222222A : 0xFFF2F2F7);
        card.setBackground(bg);

        TextView t = new TextView(this);
        t.setText("天 地 秘 境");
        t.setTextSize(19);
        t.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        t.setTextColor(0xFFFB7299);
        t.setGravity(Gravity.CENTER);
        card.addView(t, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        TextView m = new TextView(this);
        m.setText("雪线之上别有洞天。\n通关全部 40 关方可踏入；\n或持密令者先行。");
        m.setTextSize(13);
        m.setTextColor(dark ? 0xFFB9B9C2 : 0xFF666670);
        m.setGravity(Gravity.CENTER);
        m.setPadding(0, Ui.dp(10), 0, Ui.dp(4));
        card.addView(m, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        final EditText in = new EditText(this);
        in.setHint("输入密令");
        in.setTextColor(dark ? 0xFFECECF2 : 0xFF33333B);
        in.setHintTextColor(0xFF77777F);
        GradientDrawable eb = new GradientDrawable();
        eb.setCornerRadius(Ui.dp(10));
        eb.setColor(dark ? 0xFF1B1B22 : 0xFFECECF0);
        in.setBackground(eb);
        in.setPadding(Ui.dp(12), Ui.dp(10), Ui.dp(12), Ui.dp(10));
        LinearLayout.LayoutParams ilp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        ilp.topMargin = Ui.dp(12);
        card.addView(in, ilp);

        TextView ok = new TextView(this);
        ok.setText("持 令 进 入");
        ok.setTextSize(15); ok.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        ok.setTextColor(0xFFFFFFFF); ok.setGravity(Gravity.CENTER);
        GradientDrawable ob = new GradientDrawable(); ob.setCornerRadius(Ui.dp(24)); ob.setColor(0xFFFB7299);
        ok.setBackground(ob);
        LinearLayout.LayoutParams olp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(44));
        olp.topMargin = Ui.dp(16);
        card.addView(ok, olp);
        ok.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if ("Fatdog".equals(in.getText().toString().trim())) {
                    dlg.dismiss(); kunlunOpen = true; selectTab(1);
                } else {
                    Toast.makeText(MainActivity.this, "密令有误", Toast.LENGTH_SHORT).show();
                }
            }
        });

        TextView cancel = new TextView(this);
        cancel.setText("暂不进入");
        cancel.setTextSize(13); cancel.setTextColor(0xFF8A8A92);
        cancel.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        clp.topMargin = Ui.dp(10);
        card.addView(cancel, clp);
        cancel.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { dlg.dismiss(); }
        });

        dlg.setContentView(card);
        dlg.getWindow().setBackgroundDrawable(new ColorDrawable(0x00000000));
        dlg.show();
    }

    private int passDoneCount() {
        int n = 0;
        for (String id : DivineReflectionActivity.LEVEL_IDS)
            if (PassLog.isDone(this, id)) n++;
        return n;
    }

    private View buildKunlunList() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(Ui.dp(16), Ui.dp(14), Ui.dp(16), Ui.dp(24));
        boolean dark = ThemeKit.isDark(this);

        TextView title = new TextView(this);
        title.setText("天 地 秘 境");
        title.setTextSize(22);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setTextColor(0xFFFB7299);
        title.setGravity(Gravity.CENTER);
        title.setId(R.id.kunlun_title);
        col.addView(title, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        int done = 0;
        for (int i = 1; i <= 7; i++) if (PassLog.isDone(this, "KL" + i)) done++;
        TextView wait = new TextView(this);
        wait.setText(done == 0 ? "七方天地，皆未开启" : "已登顶 " + done + " / 7");
        wait.setTextSize(13);
        wait.setTextColor(ThemeKit.muted(dark));
        wait.setGravity(Gravity.CENTER);
        wait.setId(R.id.kunlun_waiting);
        LinearLayout.LayoutParams wlp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        wlp.topMargin = Ui.dp(6);
        col.addView(wait, wlp);

        /* 分类条：与大厅同款胶囊交互 */
        HorizontalScrollView hsv = new HorizontalScrollView(this);
        hsv.setHorizontalScrollBarEnabled(false);
        LinearLayout cats = new LinearLayout(this);
        cats.setOrientation(LinearLayout.HORIZONTAL);
        cats.setPadding(Ui.dp(4), Ui.dp(12), Ui.dp(4), Ui.dp(4));
        final String[] catNames = {"昆仑山", "流沙河", "幽冥海", "太玄之初", "扶桑树"};
        for (int i = 0; i < catNames.length; i++) {
            final int idx = i;
            TextView chip = new TextView(this);
            chip.setText(catNames[i]);
            chip.setTextSize(14);
            chip.setGravity(Gravity.CENTER);
            chip.setPadding(Ui.dp(14), Ui.dp(6), Ui.dp(14), Ui.dp(6));
            GradientDrawable cg = new GradientDrawable();
            cg.setCornerRadius(Ui.dp(14));
            cg.setColor(i == kunlunCat ? 0xFFFB7299 : (dark ? 0xFF2A2A33 : 0xFFF1F1F4));
            chip.setBackground(cg);
            chip.setTextColor(i == kunlunCat ? 0xFFFFFFFF : (dark ? 0xFFD8D8E0 : 0xFF3A3A42));
            LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            clp.rightMargin = Ui.dp(8);
            cats.addView(chip, clp);
            chip.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) { kunlunCat = idx; selectTab(1); }
            });
        }
        hsv.addView(cats);
        col.addView(hsv, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        LinearLayout list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams llp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        llp.topMargin = Ui.dp(10);
        col.addView(list, llp);

        if (kunlunCat == 0) {
            String[] names = {"山门", "引雷桩", "渡鸦桥", "冰裂缝", "登顶"};
            for (int i = 1; i <= 5; i++) {
                final int lv = i;
                boolean open = PassLog.isDone(this, "KL" + i);
                Button b = new Button(this);
                b.setText("KL" + i + " · " + names[i - 1] + (open ? " ✔" : ""));
                b.setEnabled(lv == 1 || (lv == 2 && PassLog.isDone(this, "KL1")) || (lv == 3 && PassLog.isDone(this, "KL2")) || (lv == 4 && PassLog.isDone(this, "KL3")) || (lv == 5 && PassLog.isDone(this, "KL4")) || open);
                b.setAlpha(b.isEnabled() ? 1f : 0.55f);
                Ui.styleButton(b);
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
                lp.topMargin = Ui.dp(12);
                list.addView(b, lp);
                if (lv == 1) b.setOnClickListener(new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        startActivity(new Intent(MainActivity.this, kn1Activity.class));
                    }
                });
                else if (lv == 2 && PassLog.isDone(this, "KL1")) b.setOnClickListener(new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        startActivity(new Intent(MainActivity.this, kn2Activity.class));
                    }
                });
                else if (lv == 3 && PassLog.isDone(this, "KL2")) b.setOnClickListener(new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        startActivity(new Intent(MainActivity.this, kn3Activity.class));
                    }
                });
                else if (lv == 4 && PassLog.isDone(this, "KL3")) b.setOnClickListener(new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        startActivity(new Intent(MainActivity.this, kn4Activity.class));
                    }
                });
                else if (lv == 5 && PassLog.isDone(this, "KL4")) b.setOnClickListener(new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        startActivity(new Intent(MainActivity.this, kn5Activity.class));
                    }
                });
            }
        } else if (kunlunCat == 1) {
            /* 流沙河：KL6 起，编号接续昆仑山 */
            String[] names = {"冰封之钥", "裂魂之匣", "幽泉之眼", "天罡北斗", "万象归一"};
            for (int i = 0; i < names.length; i++) {
                final int kl = 6 + i;
                boolean open = PassLog.isDone(this, "KL" + kl);
                Button b = new Button(this);
                b.setText("KL" + kl + " · " + names[i] + (open ? " ✔" : ""));
                b.setEnabled(kl == 6 || PassLog.isDone(this, "KL6"));
                b.setAlpha(b.isEnabled() ? 1f : 0.55f);
                Ui.styleButton(b);
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
                lp.topMargin = Ui.dp(12);
                list.addView(b, lp);
                final Class<?> target = kl == 6 ? n43Activity.class
                        : (kl == 7 ? o44Activity.class
                        : (kl == 8 ? p45Activity.class
                        : (kl == 9 ? q46Activity.class : r47Activity.class)));
                b.setOnClickListener(new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        startActivity(new Intent(MainActivity.this, target));
                    }
                });
            }
        } else if (kunlunCat == 2) {
            /* 幽冥海：KL11 起，SO patch 对抗 */
            String[] names = {"偷梁换柱", "移花接木", "声东击西", "偷天换日", "万法归宗"};
            for (int i = 0; i < names.length; i++) {
                final int kl = 11 + i;
                boolean open = PassLog.isDone(this, "KL" + kl);
                Button b = new Button(this);
                b.setText("KL" + kl + " · " + names[i] + (open ? " ✔" : ""));
                b.setEnabled(kl == 11 || PassLog.isDone(this, "KL" + (kl - 1)));
                b.setAlpha(b.isEnabled() ? 1f : 0.55f);
                Ui.styleButton(b);
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
                lp.topMargin = Ui.dp(12);
                list.addView(b, lp);
                final Class<?> target = kl == 11 ? s48Activity.class
                        : (kl == 12 ? t49Activity.class
                        : (kl == 13 ? u50Activity.class
                        : (kl == 14 ? v51Activity.class
                        : (kl == 15 ? x52Activity.class : null))));
                if (target != null) {
                    b.setOnClickListener(new View.OnClickListener() {
                        @Override public void onClick(View v) {
                            startActivity(new Intent(MainActivity.this, target));
                        }
                    });
                }
            }
        } else if (kunlunCat == 3) {
            /* 太玄之初：KL16 起，三代壳保护 */
            String[] names = {"破壳新生", "金蝉脱壳", "乾坤迷阵", "虚空造化", "破壁飞升"};
            for (int i = 0; i < names.length; i++) {
                final int kl = 16 + i;
                boolean open = PassLog.isDone(this, "KL" + kl);
                Button b = new Button(this);
                b.setText("KL" + kl + " · " + names[i] + (open ? " ✔" : ""));
                b.setEnabled(kl == 16 || PassLog.isDone(this, "KL" + (kl - 1)));
                b.setAlpha(b.isEnabled() ? 1f : 0.55f);
                Ui.styleButton(b);
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
                lp.topMargin = Ui.dp(12);
                list.addView(b, lp);
                final Class<?> target = kl == 16 ? y53Activity.class
                        : (kl == 17 ? z54Activity.class
                        : (kl == 18 ? a55Activity.class
                        : (kl == 19 ? b56Activity.class
                        : (kl == 20 ? c57Activity.class : null))));
                if (target != null) {
                    b.setOnClickListener(new View.OnClickListener() {
                        @Override public void onClick(View v) {
                            startActivity(new Intent(MainActivity.this, target));
                        }
                    });
                }
            }
        } else if (kunlunCat == 4) {
            /* 扶桑树：KL21 起，Frida 检测对抗 */
            String[] names = {"枯叶听风", "落影寻痕"};
            int[] klNums = {21, 22};
            for (int i = 0; i < names.length; i++) {
                final int kl = klNums[i];
                boolean open = PassLog.isDone(this, "KL" + kl);
                Button b = new Button(this);
                b.setText("KL" + kl + " · " + names[i] + (open ? " ✔" : ""));
                b.setEnabled(kl == 21 || PassLog.isDone(this, "KL" + (kl - 1)));
                b.setAlpha(b.isEnabled() ? 1f : 0.55f);
                Ui.styleButton(b);
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
                lp.topMargin = Ui.dp(12);
                list.addView(b, lp);
                final Class<?> target = kl == 21 ? c58Activity.class
                        : (kl == 22 ? d59Activity.class : null);
                if (target != null) {
                    b.setOnClickListener(new View.OnClickListener() {
                        @Override public void onClick(View v) {
                            startActivity(new Intent(MainActivity.this, target));
                        }
                    });
                }
            }
        }

        scroll.addView(col);
        return scroll;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}