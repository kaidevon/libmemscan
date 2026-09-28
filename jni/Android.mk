LOCAL_PATH := $(call my-dir)

BUILD_TYPE ?= shared

ifeq ($(BUILD_TYPE),static)
    MY_BUILD_LIBRARY := $(BUILD_STATIC_LIBRARY)
else
    MY_BUILD_LIBRARY := $(BUILD_SHARED_LIBRARY)
endif

MEMSCAN_SRCS := $(wildcard $(LOCAL_PATH)/../src/*.c)
MEMSCAN_SRCS := $(patsubst $(LOCAL_PATH)/%,%,$(MEMSCAN_SRCS))

include $(CLEAR_VARS)
LOCAL_MODULE            := libmemscan
LOCAL_SRC_FILES         := $(MEMSCAN_SRCS)
LOCAL_C_INCLUDES        := $(LOCAL_PATH)/../include
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../include
LOCAL_CFLAGS            := -fPIC -O3 -D_GNU_SOURCE
ifneq ($(BUILD_TYPE),static)
    LOCAL_LDLIBS        := -llog
endif
include $(MY_BUILD_LIBRARY)