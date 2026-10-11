package com.fatdog.reverse;

import android.app.Activity;
import android.os.Bundle;

// 天地秘境·太玄之初 KL17「金蝉脱壳」。
// 原设计为"类抽取的语义模拟"（标记拆 4 段散在 fill_seg0..3，无真实加密 DEX），
// 与"脱壳实训"定位不符，已下架重制 —— 现渲染维护页并直接给出答案（见 Upkeep）。
public class hollowActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(Upkeep.page(this, R.drawable.level_kl17, "KL17", "金蝉脱壳", "49227"));
        ThemeKit.apply(this);
    }
}
