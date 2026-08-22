.PHONY: kernel kernel-deploy driver-builtin driver-dkms

# -- Kernel cross-compilation with debug config
# Builds the official Pi kernel (bcm2711_defconfig) with kernel/debug.config merged in.
#
# Prereqs (one-time):  sudo apt install gcc-aarch64-linux-gnu flex bison libssl-dev libelf-dev bc

kernel: $(KERNEL_OUT)/arch/arm64/boot/Image

$(KERNEL_OUT)/arch/arm64/boot/Image: $(DEBUG_CONFIG)
	@command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 \
	    || { echo "Error: install gcc-aarch64-linux-gnu flex bison libssl-dev libelf-dev bc"; exit 1; }
	[ -d $(KERNEL_SRC)/.git ] || git clone --depth=1 --branch rpi-6.6.y $(KERNEL_REPO) $(KERNEL_SRC)
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- bcm2711_defconfig
	grep -E '^CONFIG_[A-Z0-9_]+=[yn]' $(DEBUG_CONFIG) | while IFS='=' read -r k v; do \
	    case "$$v" in \
	        y) $(KERNEL_SRC)/scripts/config --file $(KERNEL_OUT)/.config --enable  "$$k" ;; \
	        n) $(KERNEL_SRC)/scripts/config --file $(KERNEL_OUT)/.config --disable "$$k" ;; \
	    esac; done
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
	    -j$(shell nproc) Image modules dtbs

kernel-deploy: $(KERNEL_OUT)/arch/arm64/boot/Image
	@test -n "$(PI)" || { echo "Error: PI not set. Usage: make kernel-deploy PI=<addr>"; exit 1; }
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
	    INSTALL_MOD_PATH=$(KERNEL_MODS) -j$(shell nproc) modules_install
	rsync -az --delete --info=progress2 $(KERNEL_MODS)/lib/modules/ $(PI_USER)@$(PI):/tmp/new-modules/
	$(SSH) "sudo rsync -a /tmp/new-modules/. /lib/modules/ && sudo depmod -a"
	scp $(KERNEL_OUT)/arch/arm64/boot/Image $(PI_USER)@$(PI):/tmp/kernel8.img
	$(SSH) "sudo cp /boot/firmware/kernel8.img /boot/firmware/kernel8.img.bak \
	    && sudo cp /tmp/kernel8.img /boot/firmware/kernel8.img && sudo reboot"
	@echo "==> Kernel deployed. Pi rebooting — reconnect in ~30 s."
	@echo "    Rollback: $(SSH) 'sudo cp /boot/firmware/kernel8.img.bak /boot/firmware/kernel8.img && sudo reboot'"

# -- Driver switching: DKMS vs in-kernel
# DKMS modules shadow in-kernel ones when installed; removing them restores in-kernel.
# Source stays on disk so driver-dkms can reinstall without re-downloading.

driver-builtin:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	$(SSH) "sudo dkms status 2>/dev/null \
	    | grep -oP '^[\w-]+/[\d.]+' | sort -u \
	    | xargs -rI{} sudo dkms remove {} --all 2>/dev/null; sudo depmod -a"
	@echo "==> DKMS removed — in-kernel drivers active after adapter reinsertion"
	@echo "    Restore: make driver-dkms PI=$(PI)"

driver-dkms:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	$(SSH) "sudo bash /usr/local/bin/wpa3-drivers.sh"
	@echo "==> DKMS drivers reinstalled"
