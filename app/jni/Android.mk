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

# L37b 篡墨之谜（魔改 MD5：IV + T 表换血；C++17 类封装 + 命名空间）
include $(CLEAR_VARS)
LOCAL_MODULE := ink
LOCAL_SRC_FILES := ink.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
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

# KL28 扶桑树 雪落无痕（C++ OOP：8 路评分阈值制 + 加载期检测 + 注入痕迹层，Probe 抽象基类虚派发 + RAII）
include $(CLEAR_VARS)
LOCAL_MODULE := snow
LOCAL_SRC_FILES := snow.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog -ldl
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

# L48 —— 10 个 so（1 真 + 9 干扰，名字不体现关卡号）
include $(CLEAR_VARS)
LOCAL_MODULE := beetle
LOCAL_SRC_FILES := beetle.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := cobalt
LOCAL_SRC_FILES := cobalt.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := heron
LOCAL_SRC_FILES := heron.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := ledger
LOCAL_SRC_FILES := ledger.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := magpie
LOCAL_SRC_FILES := magpie.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := pelican
LOCAL_SRC_FILES := pelican.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := tariff
LOCAL_SRC_FILES := tariff.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := voucher
LOCAL_SRC_FILES := voucher.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := walrus
LOCAL_SRC_FILES := walrus.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := badger
LOCAL_SRC_FILES := badger.cpp
include $(BUILD_SHARED_LIBRARY)

# L49 —— 10 个 so（1 真 + 9 干扰，名字不体现关卡号）
include $(CLEAR_VARS)
LOCAL_MODULE := cargo
LOCAL_SRC_FILES := cargo.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := dispatch
LOCAL_SRC_FILES := dispatch.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := escrow
LOCAL_SRC_FILES := escrow.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := falcon
LOCAL_SRC_FILES := falcon.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := gecko
LOCAL_SRC_FILES := gecko.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := hornet
LOCAL_SRC_FILES := hornet.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := lynx
LOCAL_SRC_FILES := lynx.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := payroll
LOCAL_SRC_FILES := payroll.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := quartz
LOCAL_SRC_FILES := quartz.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := otter
LOCAL_SRC_FILES := otter.cpp
include $(BUILD_SHARED_LIBRARY)

# L50 —— 10 个 so（1 真 + 9 干扰，名字不体现关卡号）
include $(CLEAR_VARS)
LOCAL_MODULE := cricket
LOCAL_SRC_FILES := cricket.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := granite
LOCAL_SRC_FILES := granite.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := ibex
LOCAL_SRC_FILES := ibex.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := invoice
LOCAL_SRC_FILES := invoice.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := koala
LOCAL_SRC_FILES := koala.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := manifest
LOCAL_SRC_FILES := manifest.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := mink
LOCAL_SRC_FILES := mink.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := parcel
LOCAL_SRC_FILES := parcel.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := vendor
LOCAL_SRC_FILES := vendor.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := crane
LOCAL_SRC_FILES := crane.cpp
include $(BUILD_SHARED_LIBRARY)

# L51 —— 10 个 so（1 真 + 9 干扰，名字不体现关卡号）
include $(CLEAR_VARS)
LOCAL_MODULE := audit
LOCAL_SRC_FILES := audit.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := bond
LOCAL_SRC_FILES := bond.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := courier
LOCAL_SRC_FILES := courier.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := freight
LOCAL_SRC_FILES := freight.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := newt
LOCAL_SRC_FILES := newt.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := quota
LOCAL_SRC_FILES := quota.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := salmon
LOCAL_SRC_FILES := salmon.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := weasel
LOCAL_SRC_FILES := weasel.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := turtle
LOCAL_SRC_FILES := turtle.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := shark
LOCAL_SRC_FILES := shark.cpp
LOCAL_LDLIBS := -ldl
include $(BUILD_SHARED_LIBRARY)

# L52 —— 10 个 so（1 真 + 9 干扰，名字不体现关卡号）
include $(CLEAR_VARS)
LOCAL_MODULE := banking
LOCAL_SRC_FILES := banking.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := dingo
LOCAL_SRC_FILES := dingo.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := eagle
LOCAL_SRC_FILES := eagle.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := finch
LOCAL_SRC_FILES := finch.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := fund
LOCAL_SRC_FILES := fund.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := registry
LOCAL_SRC_FILES := registry.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := retail
LOCAL_SRC_FILES := retail.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := tender
LOCAL_SRC_FILES := tender.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := cobra
LOCAL_SRC_FILES := cobra.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := moose
LOCAL_SRC_FILES := moose.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

# L53 —— 10 个 so（1 真 + 9 干扰，名字不体现关卡号）
include $(CLEAR_VARS)
LOCAL_MODULE := customs
LOCAL_SRC_FILES := customs.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := lemur
LOCAL_SRC_FILES := lemur.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := panda
LOCAL_SRC_FILES := panda.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := quail
LOCAL_SRC_FILES := quail.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := rebate
LOCAL_SRC_FILES := rebate.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := robin
LOCAL_SRC_FILES := robin.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := seal
LOCAL_SRC_FILES := seal.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := zebra
LOCAL_SRC_FILES := zebra.cpp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := viper
LOCAL_SRC_FILES := viper.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := tapir
LOCAL_SRC_FILES := tapir.cpp
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti
LOCAL_LDLIBS := -llog -ldl
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

# KL51 迷阵 迷雾初开（C++ OOP + OLLVM 控制流平坦化：switch dispatcher + 虚派发 AES/HMAC，Base64 藏钥）
include $(CLEAR_VARS)
LOCAL_MODULE := fog
LOCAL_SRC_FILES := fog.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL52 迷阵 虚实相生（C++ OOP + OLLVM 虚假控制流：不透明谓词 + 克隆形变块 + 虚派发 SM4/SHA256，Base64 藏钥）
include $(CLEAR_VARS)
LOCAL_MODULE := phantom
LOCAL_SRC_FILES := phantom.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL53 迷阵 移形换位（C++ OOP + OLLVM 字符串加密：三变体解密平坦化 + 虚派发 AES-CBC/MD5 + JNI_OnLoad 分发器）
include $(CLEAR_VARS)
LOCAL_MODULE := shift
LOCAL_SRC_FILES := shift.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL54 迷阵 困兽犹斗（C++ OOP + 魔改 FLA：中间块链 + 加密跳转表间接派发 + 真指令替换 + 虚派发魔改 SM4 + JNI_OnLoad 分发器）
include $(CLEAR_VARS)
LOCAL_MODULE := beast
LOCAL_SRC_FILES := beast.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL55 迷阵 破阵而出（C++ OOP + 手写 OLLVM 综合收官：三级状态机 + 支配节点 key + 异常边 + 虚派发魔改 AES/魔改 Base64 响应 + JNI_OnLoad 分发器）
include $(CLEAR_VARS)
LOCAL_MODULE := gate
LOCAL_SRC_FILES := gate.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)
