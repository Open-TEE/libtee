LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  libtee
LOCAL_SRC_FILES	    :=  src/tee_client_api.c \
						src/com_protocol.c #\ #TODO
#						../../system/core/libcutils/ashmem-dev.c  #this should target the root of the android sourcetree directory but it can't find it

LOCAL_C_FLAGS       :=  -rdynamic -DANDROID -DANDROID9 -g

LOCAL_LDLIBS   := -lz -lm # -lrt   #TODO where is lrt in the android sourcetree? This doesn't work

LOCAL_C_INCLUDES    :=  $(LOCAL_PATH)/include/ external/zlib system/code/include

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include/

include $(BUILD_SHARED_LIBRARY)
