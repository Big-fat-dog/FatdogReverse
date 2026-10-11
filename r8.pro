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

# 关卡 48：k 子包（Grain / Husk）不写 -keep class，自然落进默认重命名（类名被涂掉）。
# 但两处名字必须保留：
#   1) native 按名回调 half(int)（GetMethodID 的字符串锚点）；
#   2) 类内私有解密函数 d(int[],int,int) 被 getDeclaredMethod 按名反射调用。
-keepclassmembers class com.fatdog.reverse.k.Grain {
    public java.lang.String half(int);
    private java.lang.String d(int[], int, int);
}
-keepclassmembers class com.fatdog.reverse.k.Husk {
    public java.lang.String half(int);
    private java.lang.String d(int[], int, int);
}

# 关卡 49：m 子包（Warden / Veil）同样不写 -keep class，类名交给 R8 改名。
# 必须保留的名字：
#   1) native 按名回调 mistTail(int) / forestHead(int)（GetMethodID 的字符串锚点）；
#   2) 私有解密函数 d(int[],int) 被 getDeclaredMethod 按名反射调用。
# 注：native 侧用 NewObject 调 <init>，构造名固定为 "<init>"，无需显式 keep。
-keepclassmembers class com.fatdog.reverse.m.Warden {
    public java.lang.String mistTail(int);
    public int[] forestHead(int);
    private int[] d(int[], int);
}
-keepclassmembers class com.fatdog.reverse.m.Veil {
    public java.lang.String mistTail(int);
    public int[] forestHead(int);
    private int[] d(int[], int);
}
