# ─────────────────────────────────────────────────────────────────────────────
# Raspberry Pi 4B — image creation and deploy automation
#
# WORKFLOW — automated image:
#   1. make image                        build customized RPi OS image
#   2. make flash DISK=/dev/sdX          write to SD card  <- ERASES the card
#   3. Insert SD, connect ethernet, power on
#      Pi installs packages on first boot (~3 min). Follow with:
#        ssh pi@wpa3-tester.local 'journalctl -u wpa3-firstboot -f'
#   4. make deploy PI=wpa3-tester.local  push code + build on Pi
#   5. make run    PI=wpa3-tester.local  deploy + launch tester
#
# WORKFLOW — stock image (manual alternative to steps 1–3):
#   Flash "Raspberry Pi OS Lite (64-bit)" via rpi-imager, enable SSH,
#   boot, then: make bootstrap PI=<ip>
# ─────────────────────────────────────────────────────────────────────────────

PI_USER     ?= pi
PI_HOSTNAME ?= wpa3-tester
PI_PASSWORD ?= wpa3tester
SSH_KEY     ?= $(HOME)/.ssh/id_rsa.pub
DISK        ?=
CONFIG      ?= wpa3_test/attack_config/DoS_soft/channel_switch/external/CSA_ex.yaml

# Static IP baked into the image — also used as SSH target (PI defaults to PI_IP)
# Direct PC–Pi cable:  PI_IP=10.0.0.2  PI_GW=10.0.0.1
# Home network:        PI_IP=192.168.1.100  PI_GW=192.168.1.1
# Leave empty to use DHCP (PI will then default to PI_HOSTNAME.local)
PI_IP       ?= 10.0.0.2
PI_GW       ?= 10.0.0.1
PI_PREFIX   ?= 24
PI          ?= $(or $(PI_IP),$(PI_HOSTNAME).local)

SRC_ROOT    := $(realpath ../..)
REMOTE      := ~/wpa3_tester
REMOTE_ABS   = /home/$(PI_USER)/wpa3_tester
SSH          = ssh -o StrictHostKeyChecking=no $(PI_USER)@$(PI)
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
include mk/debug.mk

.PHONY: help
help:
	@echo ""
	@echo "  Image (first time):"
	@echo "    make image                         download + customize RPi OS image"
	@echo "    make flash DISK=/dev/sdX           write to SD card (ERASES it)"
	@echo ""
	@echo "  Deploy (iterative debugging):"
	@echo "    make bootstrap    PI=<addr>        first-time setup on stock image"
	@echo "    make deploy       PI=<addr>        rsync source + rebuild on Pi"
	@echo "    make run          PI=<addr>        deploy and launch tester"
	@echo ""
	@echo "  Cross-compilation (build on host, push binary only):"
	@echo "    make sysroot      PI=<addr>        sync Pi libs to run/cross-sysroot/ (once)"
	@echo "    make deploy-cross PI=<addr>        build for aarch64 on host, push binary"
	@echo "    make test-cross   PI=<addr>        build all tests for aarch64, deploy, run ctest on Pi"
	@echo "    make clean_cross                   remove cross build dir"
	@echo ""
	@echo "  Internet sharing (Pi has no direct internet):"
	@echo "    make internet                      NAT host internet -> Pi"
	@echo "    make internet-off                  remove NAT rules"
	@echo ""
	@echo "  Remote debugging:"
	@echo "    make run-debug    PI=<addr>        start gdbserver on Pi"
	@echo "      then: gdb-multiarch build-cross/bin/wpa3_tester"
	@echo "            (gdb) target remote <addr>:1234"
	@echo "    make debug_netcat PI=<addr>        netconsole crash log (Ctrl+C to stop)"
	@echo "      pstore log after reboot:  ssh pi@PI 'cat /sys/fs/pstore/*'"
	@echo ""
	@echo "  Kernel (debug build with all *_DEBUGFS flags):"
	@echo "    make kernel                        cross-compile Pi kernel with kernel/debug.config"
	@echo "    make kernel-deploy PI=<addr>       push kernel + modules, reboot Pi"
	@echo "    make driver-builtin PI=<addr>      remove DKMS overrides -> use in-kernel drivers"
	@echo "    make driver-dkms    PI=<addr>      reinstall DKMS drivers -> override in-kernel"
	@echo ""
	@echo "  Results:"
	@echo "    make results      PI=<addr>        sync data from Pi + generate HTML"
	@echo ""
	@echo "  Overridable defaults:"
	@echo "    PI_USER=$(PI_USER)   PI_HOSTNAME=$(PI_HOSTNAME)"
	@echo "    PI_PASSWORD=$(PI_PASSWORD)   SSH_KEY=$(SSH_KEY)"
	@echo ""
