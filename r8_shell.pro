# 太玄之初 KKL4/KKL5 多类壳的 R8 混淆规则（r8_shell.pro）。
#
# 壳类群（w.* / y.* / kkl5shell）走 R8 混淆类名——否则 javac + d8 出来类名全明文，
# 「多类壳」只剩形式。规则：
#   * 只混淆壳类群自己的包，不 shrink、不 optimize（壳类是纯逻辑，无未用代码要删）；
#   * 保留「入口类」原名（否则外部 Activity/native 无法按名进入壳）；
#   * 壳类之间靠 .class 常量串联，R8 改名后自动重写常量引用，保持自洽。

-dontshrink
-dontoptimize
-ignorewarnings

# 壳类群整体交给 R8 改名（不写 -keep class，自然落进默认重命名）。
# 但「入口类」必须保留原名，它是外部进入多类壳的唯一锚点：
#   KKL4：com.fatdog.reverse.shellw.Wick
#   KKL5：com.fatdog.reverse.shelly.Wick（外层）/ shellx.Wick（壳 A）/ shellz.Wick（壳 B）
-keep class com.fatdog.reverse.shellw.Wick { *; }
-keep class com.fatdog.reverse.shelly.Wick { *; }
-keep class com.fatdog.reverse.shellx.Wick { *; }
-keep class com.fatdog.reverse.shellz.Wick { *; }

# 壳类群引用业务片（GateKeeper4h / GateKeeper5l 等）时，业务片是 library class
# （另由 d8 编译），保留其原名，避免 R8 误改跨 dex 的类型引用。
-dontwarn com.fatdog.reverse.kkl4.**
-dontwarn com.fatdog.reverse.kkl5.**
-keep class com.fatdog.reverse.kkl4.** { *; }
-keep class com.fatdog.reverse.kkl5.** { *; }
