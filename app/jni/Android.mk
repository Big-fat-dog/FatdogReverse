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
