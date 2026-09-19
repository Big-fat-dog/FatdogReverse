LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := native
LOCAL_SRC_FILES := native.c
include $(BUILD_SHARED_LIBRARY)

# L28
include $(CLEAR_VARS)
LOCAL_MODULE := axol
LOCAL_SRC_FILES := axol.c
include $(BUILD_SHARED_LIBRARY)

# L29
include $(CLEAR_VARS)
LOCAL_MODULE := fern
LOCAL_SRC_FILES := fern.c
include $(BUILD_SHARED_LIBRARY)

# L30
include $(CLEAR_VARS)
LOCAL_MODULE := mica
LOCAL_SRC_FILES := mica.c
include $(BUILD_SHARED_LIBRARY)

# L31
include $(CLEAR_VARS)
LOCAL_MODULE := quill
LOCAL_SRC_FILES := quill.c
include $(BUILD_SHARED_LIBRARY)

# L32
include $(CLEAR_VARS)
LOCAL_MODULE := raven
LOCAL_SRC_FILES := raven.c
include $(BUILD_SHARED_LIBRARY)

# L33
include $(CLEAR_VARS)
LOCAL_MODULE := sable
LOCAL_SRC_FILES := sable.c
include $(BUILD_SHARED_LIBRARY)

# L34
include $(CLEAR_VARS)
LOCAL_MODULE := talon
LOCAL_SRC_FILES := talon.c
include $(BUILD_SHARED_LIBRARY)

# L35
include $(CLEAR_VARS)
LOCAL_MODULE := umbra
LOCAL_SRC_FILES := umbra.c
include $(BUILD_SHARED_LIBRARY)

# L36
include $(CLEAR_VARS)
LOCAL_MODULE := vigor
LOCAL_SRC_FILES := vigor.c
include $(BUILD_SHARED_LIBRARY)

# L37
include $(CLEAR_VARS)
LOCAL_MODULE := wyvern
LOCAL_SRC_FILES := wyvern.c
include $(BUILD_SHARED_LIBRARY)

# KL1
include $(CLEAR_VARS)
LOCAL_MODULE := cedar
LOCAL_SRC_FILES := cedar.c
include $(BUILD_SHARED_LIBRARY)

# KL2
include $(CLEAR_VARS)
LOCAL_MODULE := lotus
LOCAL_SRC_FILES := lotus.c
include $(BUILD_SHARED_LIBRARY)

# KL3
include $(CLEAR_VARS)
LOCAL_MODULE := maple
LOCAL_SRC_FILES := maple.c
include $(BUILD_SHARED_LIBRARY)

# KL4
include $(CLEAR_VARS)
LOCAL_MODULE := rivet
LOCAL_SRC_FILES := rivet.c
include $(BUILD_SHARED_LIBRARY)

# KL5
include $(CLEAR_VARS)
LOCAL_MODULE := tulip
LOCAL_SRC_FILES := tulip.c
include $(BUILD_SHARED_LIBRARY)

# KL6
include $(CLEAR_VARS)
LOCAL_MODULE := ember
LOCAL_SRC_FILES := ember.c
include $(BUILD_SHARED_LIBRARY)

# KL7
include $(CLEAR_VARS)
LOCAL_MODULE := frost
LOCAL_SRC_FILES := frost.c
include $(BUILD_SHARED_LIBRARY)

# KL8
include $(CLEAR_VARS)
LOCAL_MODULE := ivory
LOCAL_SRC_FILES := ivory.c
include $(BUILD_SHARED_LIBRARY)

# KL9
include $(CLEAR_VARS)
LOCAL_MODULE := jade
LOCAL_SRC_FILES := jade.c
include $(BUILD_SHARED_LIBRARY)

# KL10
include $(CLEAR_VARS)
LOCAL_MODULE := onyx
LOCAL_SRC_FILES := onyx.c
include $(BUILD_SHARED_LIBRARY)

# L44
include $(CLEAR_VARS)
LOCAL_MODULE := pearl
LOCAL_SRC_FILES := pearl.c
include $(BUILD_SHARED_LIBRARY)

# L45
include $(CLEAR_VARS)
LOCAL_MODULE := coral
LOCAL_SRC_FILES := coral.c
LOCAL_LDLIBS := -lz
include $(BUILD_SHARED_LIBRARY)

# L46
include $(CLEAR_VARS)
LOCAL_MODULE := amber
LOCAL_SRC_FILES := amber.c
include $(BUILD_SHARED_LIBRARY)

# L47
include $(CLEAR_VARS)
LOCAL_MODULE := felix
LOCAL_SRC_FILES := felix.c
include $(BUILD_SHARED_LIBRARY)

# KL11
include $(CLEAR_VARS)
LOCAL_MODULE := helix
LOCAL_SRC_FILES := helix.c
include $(BUILD_SHARED_LIBRARY)

# KL12
include $(CLEAR_VARS)
LOCAL_MODULE := kraken
LOCAL_SRC_FILES := kraken.c
include $(BUILD_SHARED_LIBRARY)

# KL13
include $(CLEAR_VARS)
LOCAL_MODULE := mantis
LOCAL_SRC_FILES := mantis.c kl13_baseline.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL14
include $(CLEAR_VARS)
LOCAL_MODULE := nebula
LOCAL_SRC_FILES := nebula.c
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := opera
LOCAL_SRC_FILES := opera.c
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := plume
LOCAL_SRC_FILES := plume.c
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

# KL15
include $(CLEAR_VARS)
LOCAL_MODULE := shale
LOCAL_SRC_FILES := shale.c shale_baseline.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL16
include $(CLEAR_VARS)
LOCAL_MODULE := ash
LOCAL_SRC_FILES := ash.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL17
include $(CLEAR_VARS)
LOCAL_MODULE := viola
LOCAL_SRC_FILES := viola.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL18
include $(CLEAR_VARS)
LOCAL_MODULE := blaze
LOCAL_SRC_FILES := blaze.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL19
include $(CLEAR_VARS)
LOCAL_MODULE := bison
LOCAL_SRC_FILES := bison.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL20
include $(CLEAR_VARS)
LOCAL_MODULE := delta
LOCAL_SRC_FILES := delta.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL21
include $(CLEAR_VARS)
LOCAL_MODULE := fox
LOCAL_SRC_FILES := fox.c
include $(BUILD_SHARED_LIBRARY)

# KL22
include $(CLEAR_VARS)
LOCAL_MODULE := owl
LOCAL_SRC_FILES := owl.c
include $(BUILD_SHARED_LIBRARY)

# KL23
include $(CLEAR_VARS)
LOCAL_MODULE := sun
LOCAL_SRC_FILES := sun.c
include $(BUILD_SHARED_LIBRARY)

# KL24
include $(CLEAR_VARS)
LOCAL_MODULE := ice
LOCAL_SRC_FILES := ice.c
include $(BUILD_SHARED_LIBRARY)

# KL25
include $(CLEAR_VARS)
LOCAL_MODULE := mist
LOCAL_SRC_FILES := mist.c
include $(BUILD_SHARED_LIBRARY)

# KL26
include $(CLEAR_VARS)
LOCAL_MODULE := dusk
LOCAL_SRC_FILES := dusk.c
include $(BUILD_SHARED_LIBRARY)

# KL27
include $(CLEAR_VARS)
LOCAL_MODULE := veil
LOCAL_SRC_FILES := veil.c
include $(BUILD_SHARED_LIBRARY)

# KL28
include $(CLEAR_VARS)
LOCAL_MODULE := snow
LOCAL_SRC_FILES := snow.c
include $(BUILD_SHARED_LIBRARY)

# KL29
include $(CLEAR_VARS)
LOCAL_MODULE := tide
LOCAL_SRC_FILES := tide.c
include $(BUILD_SHARED_LIBRARY)

# KL30
include $(CLEAR_VARS)
LOCAL_MODULE := loom
LOCAL_SRC_FILES := loom.c
include $(BUILD_SHARED_LIBRARY)

# KL36
include $(CLEAR_VARS)
LOCAL_MODULE := flutterbridge
LOCAL_SRC_FILES := kl36.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL37
include $(CLEAR_VARS)
LOCAL_MODULE := fluttercore
LOCAL_SRC_FILES := kl37.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL38
include $(CLEAR_VARS)
LOCAL_MODULE := flutternet
LOCAL_SRC_FILES := kl38.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL39
include $(CLEAR_VARS)
LOCAL_MODULE := bow
LOCAL_SRC_FILES := kl39.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL40
include $(CLEAR_VARS)
LOCAL_MODULE := rig
LOCAL_SRC_FILES := kl40.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KKL1
include $(CLEAR_VARS)
LOCAL_MODULE := kkl1
LOCAL_SRC_FILES := kkl1.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KKL2
include $(CLEAR_VARS)
LOCAL_MODULE := kkl2
LOCAL_SRC_FILES := kkl2.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KKL3
include $(CLEAR_VARS)
LOCAL_MODULE := kkl3
LOCAL_SRC_FILES := kkl3.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KKL4
include $(CLEAR_VARS)
LOCAL_MODULE := kkl4
LOCAL_SRC_FILES := kkl4.cpp kkl4_baseline.c
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KKL5
include $(CLEAR_VARS)
LOCAL_MODULE := kkl5
LOCAL_SRC_FILES := kkl5.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# L48
include $(CLEAR_VARS)
LOCAL_MODULE := native48
LOCAL_SRC_FILES := native48.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# L49
include $(CLEAR_VARS)
LOCAL_MODULE := native49
LOCAL_SRC_FILES := native49.cpp

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := native50
LOCAL_SRC_FILES := native50.cpp

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := native51
LOCAL_SRC_FILES := native51.cpp
LOCAL_LDLIBS := -ldl

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := native51h
LOCAL_SRC_FILES := native51h.cpp

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := native51b
LOCAL_SRC_FILES := native51b.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# L52
include $(CLEAR_VARS)
LOCAL_MODULE := native52
LOCAL_SRC_FILES := native52.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := native52k
LOCAL_SRC_FILES := native52k.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := native52b
LOCAL_SRC_FILES := native52b.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# L53
include $(CLEAR_VARS)
LOCAL_MODULE := native53
LOCAL_SRC_FILES := native53.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := native53c
LOCAL_SRC_FILES := native53c.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := native53b
LOCAL_SRC_FILES := native53b.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL41 须弥界 浅滩拾贝（H5 壳 / JSBridge 注入定位）
include $(CLEAR_VARS)
LOCAL_MODULE := h5shell
LOCAL_SRC_FILES := h5shell.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL42 须弥界 沙中藏贝（H5 资源加密 + JS 层加密）
include $(CLEAR_VARS)
LOCAL_MODULE := webvault
LOCAL_SRC_FILES := webvault.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL43 须弥界 桥上听风（JSBridge 协议分发）
include $(CLEAR_VARS)
LOCAL_MODULE := jsbridge
LOCAL_SRC_FILES := jsbridge.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL44 须弥界 暗流涌动（JSBridge 签名拦截 + JS 层加密 + 反调试）
include $(CLEAR_VARS)
LOCAL_MODULE := signbridge
LOCAL_SRC_FILES := signbridge.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL45 须弥界 深渊合璧（综合收官卷：JS 层 AES + native 普通 MD5 + 反调试）
include $(CLEAR_VARS)
LOCAL_MODULE := hybrid
LOCAL_SRC_FILES := hybrid.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL46 九幽 落叶归根（Root 检测与绕过：多层环境检测，评分阈值制 + SVC syscall）
include $(CLEAR_VARS)
LOCAL_MODULE := elm
LOCAL_SRC_FILES := elm.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL47 九幽 深根固蒂（Bootloader 解锁 + 系统属性深检，评分阈值制）
include $(CLEAR_VARS)
LOCAL_MODULE := oak
LOCAL_SRC_FILES := oak.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL48 九幽 斩草除根（挂载点/mount namespace 深检 + magiskd 进程，评分阈值制）
include $(CLEAR_VARS)
LOCAL_MODULE := yew
LOCAL_SRC_FILES := yew.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL49 九幽 盘根错节（新一代 root KernelSU/APatch 检测 + Play Integrity 本地仿真）
include $(CLEAR_VARS)
LOCAL_MODULE := ivy
LOCAL_SRC_FILES := ivy.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL50 九幽 枯木逢春（综合收官卷：全维度检测 + SVC + 反调试 + 静默投毒）
include $(CLEAR_VARS)
LOCAL_MODULE := dew
LOCAL_SRC_FILES := dew.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL51 迷阵 迷雾初开（OLLVM 控制流平坦化基础：switch dispatcher + AES + HMAC，Base64 藏钥）
include $(CLEAR_VARS)
LOCAL_MODULE := fog
LOCAL_SRC_FILES := fog.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL52 迷阵 虚实相生（OLLVM 虚假控制流：不透明谓词 + 不可达虚假块 + SM4 + SHA256，Base64 藏钥）
include $(CLEAR_VARS)
LOCAL_MODULE := phantom
LOCAL_SRC_FILES := phantom.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)
