LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  libtee
LOCAL_SRC_FILES	    :=  src/tee_client_api.c \
						src/com_protocol.c \
						../emulator/include/cutils/ashmem-dev.c

LOCAL_C_FLAGS       :=  -rdynamic -DANDROID -DANDROID9 -g #-O3 -D_LINUX_IPC

LOCAL_LDLIBS   := -lz -lm

LOCAL_SHARED_LIBRARIES  := -lrt

LOCAL_C_INCLUDES    :=  $(LOCAL_PATH)/include/   $(LOCAL_PATH)/../emulator/include/

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include/

include $(BUILD_SHARED_LIBRARY)
