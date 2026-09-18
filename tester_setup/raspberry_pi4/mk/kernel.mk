.PHONY: kernel kernel-deploy driver-builtin driver-dkms driver-modules

# -- Kernel cross-compilation with debug config
# Builds the official Pi kernel (bcm2711_defconfig) with kernel/debug.config merged in.
#
# Prereqs (one-time):  sudo apt install gcc-aarch64-linux-gnu flex bison libssl-dev libelf-dev bc

kernel: $(KERNEL_OUT)/arch/arm64/boot/Image

$(KERNEL_OUT)/arch/arm64/boot/Image: $(DEBUG_CONFIG)
	@command -v $(CROSS_COMPILE)gcc >/dev/null 2>&1 \
	    || { echo "Error: cross-compiler $(CROSS_COMPILE)gcc not found"; \
	         echo "  Debian/Ubuntu: sudo apt install gcc-aarch64-linux-gnu flex bison libssl-dev libelf-dev bc"; \
	         echo "  NixOS:         nix-shell  (shell.nix in this directory)"; exit 1; }
	[ -d $(KERNEL_SRC)/.git ] || git clone --depth=1 --branch rpi-6.6.y $(KERNEL_REPO) $(KERNEL_SRC)
	grep -q 'reset_resume' $(KERNEL_SRC)/drivers/net/wireless/mediatek/mt76/mt76x2/usb.c || \
	    sed -i '/\.resume\s*=\s*mt76x2u_resume/a\\t.reset_resume\t= mt76x2u_resume,' \
	    $(KERNEL_SRC)/drivers/net/wireless/mediatek/mt76/mt76x2/usb.c
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) bcm2711_defconfig
	grep -E '^CONFIG_[A-Z0-9_]+=[yn]' $(DEBUG_CONFIG) | while IFS='=' read -r k v; do \
	    case "$$v" in \
	        y) $(KERNEL_SRC)/scripts/config --file $(KERNEL_OUT)/.config --enable  "$$k" ;; \
	        n) $(KERNEL_SRC)/scripts/config --file $(KERNEL_OUT)/.config --disable "$$k" ;; \
	    esac; done
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) olddefconfig
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) \
	    -j$(shell nproc) Image modules dtbs

# -- Out-of-tree WiFi drivers, cross-built against THIS kernel's own O=$(KERNEL_OUT) tree
#  (not against apt headers)
DRIVER_SRC := run/drivers-src

define DRIVER_SPECS
rtw88|https://github.com/lwfinger/rtw88|-DCONFIG_RTW88_DEBUGFS -DCONFIG_RTW88_DEBUG
8821cu|https://github.com/morrownr/8821cu-20210916|
rtl8852au|https://github.com/WimLee115/rtl8852au-build|-DCONFIG_RTW89_DEBUGFS -DCONFIG_RTW89_8852AU -DCONFIG_RTW89_DEBUG
endef
export DRIVER_SPECS

driver-modules: $(KERNEL_OUT)/arch/arm64/boot/Image
	@echo "==> Cross-building WiFi drivers against $(KERNEL_OUT) (matches this kernel exactly)..."
	@echo "$$DRIVER_SPECS" | while IFS='|' read -r name url cflags; do \
	    [ -z "$$name" ] && continue; \
	    src=$(DRIVER_SRC)/$$name; \
	    rm -rf "$$src"; mkdir -p $(DRIVER_SRC); \
	    git clone --depth=1 "$$url" "$$src"; \
	    [ -n "$$cflags" ] && echo "EXTRA_CFLAGS += $$cflags" >> "$$src/Makefile"; \
	    $(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) \
	        M=$$(realpath $$src) modules -j$$(nproc); \
	    $(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) \
	        M=$$(realpath $$src) INSTALL_MOD_PATH=$(KERNEL_MODS) INSTALL_MOD_DIR=updates \
	        modules_install; \
	done
	@echo "==> Drivers built -> $(KERNEL_MODS)/lib/modules/*/updates/"

kernel-deploy: $(KERNEL_OUT)/arch/arm64/boot/Image
	@test -n "$(PI)" || { echo "Error: PI not set. Usage: make kernel-deploy PI=<addr>"; exit 1; }
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) \
	    INSTALL_MOD_PATH=$(KERNEL_MODS) -j$(shell nproc) modules_install
	$(MAKE) driver-modules
	rsync -az --delete --info=progress2 $(KERNEL_MODS)/lib/modules/ $(PI_USER)@$(PI):/tmp/new-modules/
	$(SSH) "sudo rsync -a /tmp/new-modules/. /lib/modules/ && sudo depmod -a"
	scp $(KERNEL_OUT)/arch/arm64/boot/Image $(PI_USER)@$(PI):/tmp/kernel8.img
	$(SSH) "sudo cp /boot/firmware/kernel8.img /boot/firmware/kernel8.img.bak \
	    && sudo cp /tmp/kernel8.img /boot/firmware/kernel8.img && sudo reboot"
	@echo "==> Kernel + drivers deployed. Pi rebooting - reconnect in ~30 s."
	@echo "    Rollback: $(SSH) 'sudo cp /boot/firmware/kernel8.img.bak /boot/firmware/kernel8.img && sudo reboot'"

# -- Driver switching: DKMS vs in-kernel
# DKMS modules shadow in-kernel ones when installed; removing them restores in-kernel.
# Source stays on disk so driver-dkms can reinstall without re-downloading.

driver-builtin:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	$(SSH) "sudo dkms status 2>/dev/null \
	    | grep -oP '^[\w-]+/[\d.]+' | sort -u \
	    | xargs -rI{} sudo dkms remove {} --all 2>/dev/null; sudo depmod -a"
	@echo "==> DKMS removed - in-kernel drivers active after adapter reinsertion"
	@echo "    Restore: make driver-dkms PI=$(PI)"

driver-dkms:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	$(SSH) "sudo bash /usr/local/bin/wpa3-drivers.sh"
	@echo "==> DKMS drivers reinstalled"