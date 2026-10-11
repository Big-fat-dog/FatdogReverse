package com.fatdog.reverse;

import android.app.Activity;
import android.os.Bundle;

// 天地秘境·太玄之初 KL16「破壳新生」。
// 原设计为"壳行为的语义模拟"（只在 .bss 里分两阶段拼回一个标记字符串，无真实加密 DEX），
// 与"脱壳实训"定位不符，已下架重制 —— 现渲染维护页并直接给出答案（见 Upkeep）。
public class gladeActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(Upkeep.page(this, R.drawable.level_kl16, "KL16", "破壳新生", "51495"));
        ThemeKit.apply(this);
    }
}
