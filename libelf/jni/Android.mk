LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libelf
# 使用相对于 LOCAL_PATH 的路径，符号链接 src -> ../src
LOCAL_SRC_FILES := $(wildcard src/*.c)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)/include/libelf
LOCAL_CFLAGS := -fPIC -Wno-unused-parameter -Wno-implicit-function-declaration
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include \
                           $(LOCAL_PATH)/include/libelf
include $(BUILD_SHARED_LIBRARY)