LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := native
LOCAL_SRC_FILES := native.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 28：缄默之钥（密钥异或藏 .rodata，运行时解码）
include $(CLEAR_VARS)
LOCAL_MODULE := l28
LOCAL_SRC_FILES := l28.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 29：隐姓埋名（JNI_OnLoad 动态注册 + 双诱饵导出）
include $(CLEAR_VARS)
LOCAL_MODULE := l29
LOCAL_SRC_FILES := l29.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 30：无名剑冢（UTF-16 藏钥 + 函数指针表派发 + 三诱饵）
include $(CLEAR_VARS)
LOCAL_MODULE := l30
LOCAL_SRC_FILES := l30.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 31：两界穿针（跨层拼装 + 干扰包）
include $(CLEAR_VARS)
LOCAL_MODULE := l31
LOCAL_SRC_FILES := l31.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 32：心魔哨兵（四路反检测 + 静默投毒）
include $(CLEAR_VARS)
LOCAL_MODULE := l32
LOCAL_SRC_FILES := l32.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 33：金刚不坏（CRC 自校验 + 记账守卫，三解全开）
include $(CLEAR_VARS)
LOCAL_MODULE := l33
LOCAL_SRC_FILES := l33.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 34：万法归墟（综合卷：动态注册+Feistel+哨兵+CRC+响应RC4）
include $(CLEAR_VARS)
LOCAL_MODULE := l34
LOCAL_SRC_FILES := l34.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 35：双匣暗渡（手写 3DES+SM4 常量识别 + 干扰包）
include $(CLEAR_VARS)
LOCAL_MODULE := l35
LOCAL_SRC_FILES := l35.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 36：查表识君（手写 AES-128，Base64 藏钥）
include $(CLEAR_VARS)
LOCAL_MODULE := l36
LOCAL_SRC_FILES := l36.c
include $(BUILD_SHARED_LIBRARY)

# 关卡 37：雪崩之谜（SHA-256 变体 IV + RC4 叠加）
include $(CLEAR_VARS)
LOCAL_MODULE := l37
LOCAL_SRC_FILES := l37.c
include $(BUILD_SHARED_LIBRARY)

# 昆仑 KL1：山门（unidbg 最小骨架）
include $(CLEAR_VARS)
LOCAL_MODULE := kunlun1
LOCAL_SRC_FILES := kunlun1.c
include $(BUILD_SHARED_LIBRARY)

# 昆仑 KL2
include $(CLEAR_VARS)
LOCAL_MODULE := kunlun2
LOCAL_SRC_FILES := kunlun2.c
include $(BUILD_SHARED_LIBRARY)

# 昆仑 KL3
include $(CLEAR_VARS)
LOCAL_MODULE := kunlun3
LOCAL_SRC_FILES := kunlun3.c
include $(BUILD_SHARED_LIBRARY)

# 昆仑 KL4
include $(CLEAR_VARS)
LOCAL_MODULE := kunlun4
LOCAL_SRC_FILES := kunlun4.c
include $(BUILD_SHARED_LIBRARY)

# 昆仑 KL5
include $(CLEAR_VARS)
LOCAL_MODULE := kunlun5
LOCAL_SRC_FILES := kunlun5.c
include $(BUILD_SHARED_LIBRARY)

# 流沙河首关：冰封之钥（魔改 AES-128，Rcon 三处换血）
include $(CLEAR_VARS)
LOCAL_MODULE := m1
LOCAL_SRC_FILES := m1.c
include $(BUILD_SHARED_LIBRARY)

# 流沙河第二关：裂魂之匣（魔改 DES，IP 换位 + S3 换值）
include $(CLEAR_VARS)
LOCAL_MODULE := m2
LOCAL_SRC_FILES := m2.c
include $(BUILD_SHARED_LIBRARY)

# 流沙河第三关：幽泉之眼（魔改 SM4，CK 尾部 8 值换血）
include $(CLEAR_VARS)
LOCAL_MODULE := m3
LOCAL_SRC_FILES := m3.c
include $(BUILD_SHARED_LIBRARY)

# 流沙河第四关：天罡北斗（魔改 RC4，KSA 初排换血 + PRGA 过掩码）
include $(CLEAR_VARS)
LOCAL_MODULE := m4
LOCAL_SRC_FILES := m4.c
include $(BUILD_SHARED_LIBRARY)

# 流沙河收官关：万象归一（魔改 SHA256 变体 + 魔改 AES 综合卷）
include $(CLEAR_VARS)
LOCAL_MODULE := m5
LOCAL_SRC_FILES := m5.c
include $(BUILD_SHARED_LIBRARY)

# 签名校验对抗 L44：偷天换日（摘要下沉 native + 记账守卫）
include $(CLEAR_VARS)
LOCAL_MODULE := m6
LOCAL_SRC_FILES := m6.c
include $(BUILD_SHARED_LIBRARY)


# 签名校验对抗 L45：移形换影（native 自读 APK 剥 PKCS#7，需要 zlib 解压条目）
include $(CLEAR_VARS)
LOCAL_MODULE := m7
LOCAL_SRC_FILES := m7.c
LOCAL_LDLIBS := -lz
include $(BUILD_SHARED_LIBRARY)

# 签名校验对抗 L46：以签为钥（证书 DER 派生 HMAC 密钥，L4 型主打）
include $(CLEAR_VARS)
LOCAL_MODULE := m8
LOCAL_SRC_FILES := m8.c
include $(BUILD_SHARED_LIBRARY)

# 签名校验对抗 L47：幽冥合卷（收官综合卷：guard矩阵+CRC+AES加密+签名）
include $(CLEAR_VARS)
LOCAL_MODULE := m9
LOCAL_SRC_FILES := m9.c
include $(BUILD_SHARED_LIBRARY)

# 幽冥海 KL11：偷梁换柱（SO patch 入门：nop 掉比较指令）
include $(CLEAR_VARS)
LOCAL_MODULE := m10
LOCAL_SRC_FILES := m10.c
include $(BUILD_SHARED_LIBRARY)

# 幽冥海 KL12：移花接木（动态 patch：Frida hook 替换返回值）
include $(CLEAR_VARS)
LOCAL_MODULE := m11
LOCAL_SRC_FILES := m11.c
include $(BUILD_SHARED_LIBRARY)

# 幽冥海 KL13：声东击西（反 patch 对抗：CRC 自校验）
include $(CLEAR_VARS)
LOCAL_MODULE    := m12
LOCAL_SRC_FILES := m12.c
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)

# 幽冥海 KL14：偷天换日（多 so 交叉验证）
include $(CLEAR_VARS)
LOCAL_MODULE    := m13a
LOCAL_SRC_FILES := m13a.c
LOCAL_LDLIBS    := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := m13b
LOCAL_SRC_FILES := m13b.c
LOCAL_LDLIBS    := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := m13c
LOCAL_SRC_FILES := m13c.c
LOCAL_LDLIBS    := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

# 幽冥海 KL15：万法归宗（综合收官卷）
include $(CLEAR_VARS)
LOCAL_MODULE    := m14
LOCAL_SRC_FILES := m14.c
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)

# 太玄之初 KL16：破壳新生（一代壳 DEX 静态加密）
include $(CLEAR_VARS)
LOCAL_MODULE    := k16
LOCAL_SRC_FILES := k16.c
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)

# 太玄之初 KL17：金蝉脱壳（二代壳 DEX 热加载 + 反调试）
include $(CLEAR_VARS)
LOCAL_MODULE    := k17
LOCAL_SRC_FILES := k17.c
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)
