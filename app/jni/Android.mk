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
LOCAL_SRC_FILES := mantis.c
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
LOCAL_SRC_FILES := shale.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL16
include $(CLEAR_VARS)
LOCAL_MODULE := taupe
LOCAL_SRC_FILES := taupe.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL17
include $(CLEAR_VARS)
LOCAL_MODULE := viola
LOCAL_SRC_FILES := viola.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL18
include $(CLEAR_VARS)
LOCAL_MODULE := blaze
LOCAL_SRC_FILES := blaze.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL19
include $(CLEAR_VARS)
LOCAL_MODULE := bison
LOCAL_SRC_FILES := bison.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# KL20
include $(CLEAR_VARS)
LOCAL_MODULE := delta
LOCAL_SRC_FILES := delta.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)
