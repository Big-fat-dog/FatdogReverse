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
