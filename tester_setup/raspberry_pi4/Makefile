# ─────────────────────────────────────────────────────────────────────────────
# Raspberry Pi 4B — image creation and deploy automation
#
# WORKFLOW — automated image:
#   1. make image                        build customized RPi OS image
#   2. make flash DISK=/dev/sdX          write to SD card  ← ERASES the card
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
CONFIG      ?= wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml
# Static IP baked into the image — also used as SSH target (PI defaults to PI_IP)
# Direct PC–Pi cable:  PI_IP=10.0.0.2  PI_GW=10.0.0.1
# Home network:        PI_IP=192.168.1.100  PI_GW=192.168.1.1
# Leave empty to use DHCP (PI will then default to PI_HOSTNAME.local)
PI_IP       ?= 10.0.0.2
PI_GW       ?= 10.0.0.1
PI_PREFIX   ?= 24
PI          ?= $(or $(PI_IP),$(PI_HOSTNAME).local)

SRC_ROOT     := $(realpath ../..)
REMOTE       := ~/wpa3_tester
REMOTE_ABS    = /home/$(PI_USER)/wpa3_tester
SSH           = ssh -o StrictHostKeyChecking=no $(PI_USER)@$(PI)
SYSROOT      := $(CURDIR)/cross-sysroot
CROSS_BUILD  := $(SRC_ROOT)/build-cross
TOOLCHAIN    := $(CURDIR)/aarch64-toolchain.cmake

RPI_IMAGE_URL := https://downloads.raspberrypi.com/raspios_lite_arm64_latest
IMAGE_XZ      := image/cache/raspios_lite_arm64.img.xz
IMAGE_RAW     := image/cache/raspios_lite_arm64.img
CUSTOM_IMAGE  := image/wpa3-tester.img

HOST_IFACE   ?= $(shell ip route get 8.8.8.8 2>/dev/null | awk '/dev/{print $$5; exit}')
PI_IFACE     ?= $(shell ip route get $(PI_IP) 2>/dev/null | awk '/dev/{print $$5; exit}')

.PHONY: help image flash bootstrap deploy run clean_image sysroot deploy-cross clean_cross internet internet-off check-internet

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
	@echo "    make sysroot      PI=<addr>        sync Pi libs to cross-sysroot/ (once)"
	@echo "    make deploy-cross PI=<addr>        build for aarch64 on host, push binary"
	@echo "    make clean_cross                   remove cross build dir"
	@echo ""
	@echo "  Internet sharing (Pi has no direct internet):"
	@echo "    make internet     PI=<addr>        NAT host internet → Pi"
	@echo "    make internet-off                  remove NAT rules"
	@echo ""
	@echo "  Overridable defaults:"
	@echo "    PI_USER=$(PI_USER)   PI_HOSTNAME=$(PI_HOSTNAME)"
	@echo "    PI_PASSWORD=$(PI_PASSWORD)   SSH_KEY=$(SSH_KEY)"
	@echo ""

# ── Image creation ─────────────────────────────────────────────────────────────

image: $(CUSTOM_IMAGE)
	@echo ""
	@echo "==> Image ready: $(CUSTOM_IMAGE)"
	@echo "    Flash:  make flash DISK=/dev/sdX"

image_default:
	make image PI_IP=10.0.0.2 PI_GW=10.0.0.1

$(CUSTOM_IMAGE): $(IMAGE_RAW) image/customize.sh image/firstboot.sh image/firstboot.service
	cp $(IMAGE_RAW) $(CUSTOM_IMAGE)
	sudo bash image/customize.sh \
		"$(CUSTOM_IMAGE)" \
		"$(PI_USER)" \
		"$(PI_PASSWORD)" \
		"$(PI_HOSTNAME)" \
		"$(SSH_KEY)" \
		"$(PI_IP)" \
		"$(PI_GW)" \
		"$(PI_PREFIX)"

$(IMAGE_RAW): $(IMAGE_XZ)
	xz --decompress --keep --stdout $(IMAGE_XZ) > $(IMAGE_RAW)

$(IMAGE_XZ):
	mkdir -p image/cache
	wget --show-progress -O $(IMAGE_XZ) $(RPI_IMAGE_URL)

# ── Flash to SD card ───────────────────────────────────────────────────────────

flash: $(CUSTOM_IMAGE)
	@test -n "$(DISK)" || { echo "Error: DISK is not set. Usage: make flash DISK=/dev/sdX"; exit 1; }
	@echo ""
	@lsblk -d -o NAME,SIZE,MODEL | grep -v loop
	@echo ""
	bash -c 'read -p "Flash $(CUSTOM_IMAGE) to $(DISK)? All data will be LOST. [y/N] " c && [ "$$c" = "y" ]'
	sudo dd if=$(CUSTOM_IMAGE) of=$(DISK) bs=4M status=progress conv=fsync
	sudo sync
	@echo ""
	@echo "==> Done. Insert SD into Pi, connect ethernet, power on."
	@echo "    Watch firstboot progress (after ~30 s):"
	@echo "      ssh $(PI_USER)@$(PI_HOSTNAME).local 'journalctl -u wpa3-firstboot -f'"
	@echo "    When complete:"
	@echo "      make deploy PI=$(PI_HOSTNAME).local"

# ── Internet sharing host → Pi (NAT via iptables) ─────────────────────────────

internet:
	@test -n "$(HOST_IFACE)" || { echo "Error: cannot detect host internet interface"; exit 1; }
	@test -n "$(PI_IFACE)"   || { echo "Error: cannot detect Pi interface (is PI_IP reachable?)"; exit 1; }
	@echo "==> Sharing internet: $(HOST_IFACE) → $(PI_IFACE) (Pi=$(PI_IP))"
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -t nat -C POSTROUTING -o $(HOST_IFACE) -j MASQUERADE 2>/dev/null || \
	    sudo iptables -t nat -A POSTROUTING -o $(HOST_IFACE) -j MASQUERADE
	sudo iptables -C FORWARD -i $(PI_IFACE) -o $(HOST_IFACE) -j ACCEPT 2>/dev/null || \
	    sudo iptables -A FORWARD -i $(PI_IFACE) -o $(HOST_IFACE) -j ACCEPT
	$(SSH) "sudo ip route replace default via $(PI_GW) && sudo sh -c 'echo nameserver 8.8.8.8 > /etc/resolv.conf'"
	@echo "==> Done. Verify with: make check-internet"

internet-off:
	sudo iptables -t nat -D POSTROUTING -o $(HOST_IFACE) -j MASQUERADE 2>/dev/null || true
	sudo iptables -D FORWARD -i $(PI_IFACE) -o $(HOST_IFACE) -j ACCEPT 2>/dev/null || true
	sudo sysctl -w net.ipv4.ip_forward=0
	@echo "==> NAT removed."

# ── Bootstrap (manual / stock image fallback) ──────────────────────────────────

bootstrap:
	@test -n "$(PI)" || { echo "Error: PI is not set. Usage: make bootstrap PI=<address>"; exit 1; }
	scp bootstrap.sh $(PI_USER)@$(PI):/tmp/bootstrap.sh
	$(SSH) "chmod +x /tmp/bootstrap.sh && /tmp/bootstrap.sh"

# ── Fast update cycle (debugging) ──────────────────────────────────────────────

deploy:
	@test -n "$(PI)" || { echo "Error: PI is not set. Usage: make deploy PI=<address>"; exit 1; }
	rsync -az --delete --info=progress2 \
		--exclude='.git/' \
		--exclude='build/' \
		--exclude='build-cross/' \
		--exclude='data/' \
		$(SRC_ROOT)/ $(PI_USER)@$(PI):$(REMOTE)/
	$(SSH) "make -C $(REMOTE) -j$$(nproc) compile"

run:
	$(SSH) -t "sudo $(REMOTE)/build/bin/wpa3_tester --config $(REMOTE)/$(CONFIG)"

# ── Cross-compilation ──────────────────────────────────────────────────────────
# Requires on host (one-time):
#   sudo apt install clang lld gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
#   gcc-aarch64-linux-gnu  — crtbeginS.o, libgcc (C runtime)
#   g++-aarch64-linux-gnu  — libstdc++ (C++ runtime)
# One-time sysroot sync, then fast iterative deploy-cross.

sysroot:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	mkdir -p \
		$(SYSROOT)/usr/include \
		$(SYSROOT)/usr/lib/aarch64-linux-gnu \
		$(SYSROOT)/usr/share/pkgconfig \
		$(SYSROOT)/lib/aarch64-linux-gnu
	rsync -az  --info=progress2 $(PI_USER)@$(PI):/usr/include/                $(SYSROOT)/usr/include/
	rsync -az  --info=progress2 $(PI_USER)@$(PI):/usr/lib/aarch64-linux-gnu/  $(SYSROOT)/usr/lib/aarch64-linux-gnu/
	rsync -az  --info=progress2 $(PI_USER)@$(PI):/lib/aarch64-linux-gnu/      $(SYSROOT)/lib/aarch64-linux-gnu/
	rsync -az  --info=progress2 $(PI_USER)@$(PI):/usr/share/pkgconfig/        $(SYSROOT)/usr/share/pkgconfig/
	# libc.so linker script references /lib/ld-linux-aarch64.so.1 with absolute path
	ln -sf aarch64-linux-gnu/ld-linux-aarch64.so.1 $(SYSROOT)/lib/ld-linux-aarch64.so.1
	@echo "==> Sysroot ready: $(SYSROOT)"
	@echo "    Re-run after installing new packages on Pi."

deploy-cross:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	@test -d "$(SYSROOT)" || { echo "Error: sysroot missing — run 'make sysroot' first"; exit 1; }
	PKG_CONFIG_SYSROOT_DIR=$(SYSROOT) \
	PKG_CONFIG_PATH=$(SYSROOT)/usr/lib/aarch64-linux-gnu/pkgconfig:$(SYSROOT)/usr/share/pkgconfig \
	cmake -S $(SRC_ROOT) -B $(CROSS_BUILD) -G Ninja \
		-DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DCMAKE_SYSROOT=$(SYSROOT) \
		-DCMAKE_BUILD_TYPE=Debug \
		-DWPA3_PROJECT_ROOT=$(REMOTE_ABS)/wpa3_test
	cmake --build $(CROSS_BUILD) --target wpa3_tester -j$(shell nproc)
	rsync -az --info=progress2 \
		$(CROSS_BUILD)/bin/wpa3_tester \
		$(PI_USER)@$(PI):$(REMOTE)/build/bin/wpa3_tester
	@echo "==> Binary deployed. Run: make run"

# ── Cleanup ────────────────────────────────────────────────────────────────────

clean_image:
	rm -f $(CUSTOM_IMAGE)
	@echo "Base image cache kept in image/cache/. Remove manually if needed."

clean_cross:
	rm -rf $(CROSS_BUILD)

