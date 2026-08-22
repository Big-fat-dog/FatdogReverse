# Fatdemo R8 混淆规则（仅关卡 19 生效）
# 思路：整个 App 交给 R8 混淆，但用 keep 规则把所有"要给学生读"的类保留原名，
# 只放行 com.fatdog.reverse.o.**（关卡 19 的加密包）让 R8 重命名成 a/b/c。

-dontshrink
-dontoptimize
-ignorewarnings

# 保留根包全部关卡/组件/工具类（含匿名内部类，$N 也要可读）
-keep class com.fatdog.reverse.* { *; }
-keep class com.fatdog.reverse.*$* { *; }

# 保留第三方库类（OkHttp / okio / Kotlin 标准库），混淆它们会出事
-keep class okhttp3.** { *; }
-keep class okio.** { *; }
-keep class kotlin.** { *; }

# 注：com.fatdog.reverse.o.** 不在此列 → R8 会把 Encrypt/Keys/Api/Dummy 重命名为 a/b/c，
# 算法名/路径/密钥仍是异或加密串（字符串加密在源码里手动做了，R8 本身不加密字符串）。

# 关卡 31：q 包类整体交给 R8 改名，但 native 回调依赖的方法名必须保留
-keepclassmembers class com.fatdog.reverse.q.Ke { public static java.lang.String partA(); }
