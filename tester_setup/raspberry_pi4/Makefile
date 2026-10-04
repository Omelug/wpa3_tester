#TODO update
# Raspberry Pi 4B - image creation and deploy automation
#
# WORKFLOW - for image (default config):
#	1. make image						full image with custom kernel + drivers etc.
#   2. make flash DISK=/dev/sdX          write to SD card  <- ERASES the card
#   3. Insert SD, connect ethernet, power on
#      Pi installs packages on first boot (~3 min)
# 	   ( follow with: ssh pi@10.0.0.2 'journalctl -u wpa3-firstboot -f')
#   4. make deploy PI=wpa3-tester.local  push code + build on Pi
#   5. make run_test TEST=<test_name>  deploy + launch tester
#   6. make run TEST_SUITE=<test_suite_name>  deploy + launch tester

PI_USER     ?= pi
PI_HOSTNAME ?= wpa3_tester
PI_PASSWORD ?= wpa3_tester
SSH_KEY     ?= $(HOME)/.ssh/id_rsa.pub
DISK        ?=
CONFIG      ?= wpa3_test/attack_config/DoS_soft/channel_switch/external/CSA_ex.yaml

# Static IP baked into the image - also used as SSH target (PI defaults to PI_IP)
# Direct PC-Pi cable:  PI_IP=10.0.0.2  PI_GW=10.0.0.1
PI_IP       ?= 10.0.0.2
PI_GW       ?= 10.0.0.1
PI_PREFIX   ?= 24
PI          ?= $(or $(PI_IP),$(PI_HOSTNAME).local) #TODO hostname DOnt works, delete ?

SRC_ROOT    := $(realpath ../..)
REMOTE      := ~/wpa3_tester
REMOTE_ABS   = /home/$(PI_USER)/wpa3_tester
_REAL_USER   := $(or $(SUDO_USER),$(USER))
SSH_KEY_PRIV ?= /home/$(_REAL_USER)/.ssh/id_rsa
_SSH_OPTS    := -o StrictHostKeyChecking=no -o ControlMaster=auto -o ControlPath=$(HOME)/.ssh/wpa3-ctl-%r@%h:%p -o ControlPersist=120s -i $(SSH_KEY_PRIV)
SSH          = ssh $(_SSH_OPTS) $(PI_USER)@$(PI)
RSYNC        = rsync -e "ssh $(_SSH_OPTS)"
SYSROOT     := $(CURDIR)/run/cross-sysroot
CROSS_BUILD := $(CURDIR)/run/build-cross
TOOLCHAIN   := $(CURDIR)/aarch64-toolchain.cmake

RPI_IMAGE_URL := https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2026-06-19/2026-06-18-raspios-trixie-arm64-lite.img.xz
IMAGE_XZ      := run/cache/raspios_lite_arm64.img.xz
IMAGE_RAW     := run/cache/raspios_lite_arm64.img
CUSTOM_IMAGE  := run/wpa3-tester.img

HOST_IFACE  ?= $(shell ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<NF;i++) if($$i=="dev"){print $$(i+1); exit}}')
PI_IFACE    ?= $(shell ip route get $(PI_IP) 2>/dev/null | awk '{for(i=1;i<NF;i++) if($$i=="dev"){print $$(i+1); exit}}')
HOST_IP     ?= $(PI_GW)
NETCAT_PORT ?= 6666

CROSS_COMPILE ?= aarch64-linux-gnu-

KERNEL_REPO  := https://github.com/raspberrypi/linux
KERNEL_SRC   := $(CURDIR)/run/kernel-src
KERNEL_OUT   := $(CURDIR)/run/kernel-build
KERNEL_MODS  := $(CURDIR)/run/kernel-modules
DEBUG_CONFIG := $(CURDIR)/kernel/debug.config

include mk/image.mk
include mk/internet.mk
include mk/deploy.mk
include mk/cross.mk
include mk/kernel.mk
include mk/results.mk

.PHONY: help
#TODO nedát to jako file do doc abych to nemusel udržovat zvlášť (už jsou tu v2ci, co nejsou pravda)
help:
	@echo "Check Makefile " #TODO add link to this file
