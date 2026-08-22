package com.fatdog.reverse;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
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
// 昆仑山 = 困难关卡（待开发）；个人主页 = 修仙境界。
public class MainActivity extends Activity {
    private static final int ACTIVE_COLOR = 0xFFFB7299;   // bilibili 粉
    private static final int REQ_AVATAR = 1001;

    private static final String[] CATS = {"静态分析", "Smali 挑战", "Frida Hook（Java 层）", "网络对抗", "SSL 抓包"};
    private static final int[][] CAT_IDS = {
            {R.id.btn_vault, R.id.btn_note, R.id.btn_puzzle, R.id.btn_gate, R.id.btn_config},
            {R.id.btn_vip, R.id.btn_activate, R.id.btn_pro, R.id.btn_ad20},
            {R.id.btn_h10, R.id.btn_h11, R.id.btn_aes12, R.id.btn_dual13, R.id.btn_chain14},
            {R.id.btn_pages15, R.id.btn_rc16, R.id.btn_f17, R.id.btn_r18, R.id.btn_l19},
            {R.id.btn_t21, R.id.btn_p22, R.id.btn_w23, R.id.btn_g24, R.id.btn_n25, R.id.btn_m26, R.id.btn_f27},
    };

    private FrameLayout host;
    private View levelsPage, kunlunPage, profilePage;

    private View tabLevels, tabKunlun, tabProfile;
    private ImageView imgLevels, imgKunlun, imgProfile;
    private TextView labelLevels, labelKunlun, labelProfile;
    private View bottomNav;

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
                selectTab(1);
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

    // 昆仑山页面的品牌色标题在主题上色后补回来
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

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}