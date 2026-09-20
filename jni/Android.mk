LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libelf
LOCAL_SRC_FILES := ../lib/$(TARGET_ARCH_ABI)/libelf.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libmemscan
LOCAL_SRC_FILES := \
    src/addr_list_filter.c \
    src/memscan.c \
    src/vma_filter.c \
    src/vm_area.c
    
LOCAL_C_INCLUDES := include \
                    $(LOCAL_PATH)/../uthash/src
LOCAL_SHARED_LIBRARIES := libelf
LOCAL_CFLAGS := -fPIC
include $(BUILD_SHARED_LIBRARY)