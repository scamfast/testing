TARGET = iphone:clang:latest:15.0
ARCHS = arm64 arm64e

TWEAK_NAME = libSystemExt
libSystemExt_FILES = main.m fishhook.c
libSystemExt_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
libSystemExt_FRAMEWORKS = UIKit AVFoundation CoreMedia CoreVideo Security
libSystemExt_LDFLAGS = -Wl,-undefined,dynamic_lookup

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
