LOCAL_PATH := $(call my-dir)

BUILD_TYPE ?= shared

ifeq ($(BUILD_TYPE),static)
    MY_BUILD_LIBRARY  := $(BUILD_STATIC_LIBRARY)
    MY_DEPENDENCY_VAR := LOCAL_STATIC_LIBRARIES
else
    MY_BUILD_LIBRARY  := $(BUILD_SHARED_LIBRARY)
    MY_DEPENDENCY_VAR := LOCAL_SHARED_LIBRARIES
endif

LIBELF_SRCS := $(wildcard $(LOCAL_PATH)/../libelf/src/*.c)
LIBELF_SRCS := $(patsubst $(LOCAL_PATH)/%,%,$(LIBELF_SRCS))

include $(CLEAR_VARS)
LOCAL_MODULE            := libelf
LOCAL_SRC_FILES         := $(LIBELF_SRCS)
LOCAL_C_INCLUDES        := \
    $(LOCAL_PATH)/../libelf/include \
    $(LOCAL_PATH)/../libelf/include/libelf
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../libelf/include
LOCAL_CFLAGS            := -D_GNU_SOURCE -fPIC \
                           -Wno-unused-parameter \
                           -Wno-implicit-function-declaration
include $(MY_BUILD_LIBRARY)

MEMSCAN_SRCS := $(wildcard $(LOCAL_PATH)/../src/*.c)
MEMSCAN_SRCS := $(patsubst $(LOCAL_PATH)/%,%,$(MEMSCAN_SRCS))

include $(CLEAR_VARS)
LOCAL_MODULE            := libmemscan
LOCAL_SRC_FILES         := $(MEMSCAN_SRCS)
LOCAL_C_INCLUDES        := $(LOCAL_PATH)/../include
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../include
$(MY_DEPENDENCY_VAR)    := libelf
LOCAL_CFLAGS            := -fPIC -O3
ifneq ($(BUILD_TYPE),static)
    LOCAL_LDLIBS        := -llog
endif
include $(MY_BUILD_LIBRARY)