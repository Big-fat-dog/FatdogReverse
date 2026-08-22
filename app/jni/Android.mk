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
