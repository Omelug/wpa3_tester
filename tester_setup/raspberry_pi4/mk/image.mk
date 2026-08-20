.PHONY: image flash clean_image ssh_first

# source files — exist in repo, no recipe needed; declared so CLion resolves them as prerequisites
image/customize.sh image/firstboot.sh image/firstboot.service: ;

image: $(CUSTOM_IMAGE)
	@echo ""
	@echo "==> Image ready: $(CUSTOM_IMAGE)"
	@echo "    Flash:  make flash DISK=/dev/sdX"

$(CUSTOM_IMAGE): $(IMAGE_RAW) $(KERNEL_OUT)/arch/arm64/boot/Image image/customize.sh image/firstboot.sh image/firstboot.service
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_OUT) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
	    INSTALL_MOD_PATH=$(KERNEL_MODS) -j$(shell nproc) modules_install
	cp $(IMAGE_RAW) $(CUSTOM_IMAGE)
	sudo bash image/customize.sh \
		"$(CUSTOM_IMAGE)" \
		"$(PI_USER)" \
		"$(PI_PASSWORD)" \
		"$(PI_HOSTNAME)" \
		"$(SSH_KEY)" \
		"$(PI_IP)" \
		"$(PI_GW)" \
		"$(PI_PREFIX)" \
		"$(KERNEL_OUT)/arch/arm64/boot/Image" \
		"$(KERNEL_MODS)/lib/modules"

$(IMAGE_RAW): $(IMAGE_XZ)
	xz --decompress --keep --stdout $(IMAGE_XZ) > $(IMAGE_RAW)

$(IMAGE_XZ):
	mkdir -p run/cache
	wget --show-progress -O $(IMAGE_XZ) $(RPI_IMAGE_URL)

flash: $(CUSTOM_IMAGE)
	@echo ""
	@lsblk -d -o NAME,SIZE,MODEL | grep -v loop
	@echo ""
	@bash -c '\
	    DISK="$(DISK)"; \
	    if [ -z "$$DISK" ]; then \
	        read -p "Enter SD card device (e.g. /dev/sdb): " DISK; \
	    fi; \
	    test -n "$$DISK" || { echo "Error: no device entered"; exit 1; }; \
	    \
	    if [[ "$$DISK" =~ ^/dev/(nvme[0-9]n[1-9]|sda|sdb|hda|hdb)$$ ]]; then \
        	ROOT_DISK=$$(lsblk -no pkname $$(findmnt -n -o TARGET /) 2>/dev/null); \
          	TARGET_NAME=$$(basename "$$DISK"); \
        	if [ "$$ROOT_DISK" = "$$TARGET_NAME" ]; then \
        		echo "You tried flash it on your disk ($$DISK)! Blocked!"; \
        		exit 1; \
        	fi; \
        fi; \
        \
	    read -p "Flash $(CUSTOM_IMAGE) to $$DISK? All data will be LOST. [y/N] " c && [ "$$c" = "y" ] || exit 1; \
	    if command -v bmaptool >/dev/null 2>&1; then \
	        sudo bmaptool copy --nobmap $(CUSTOM_IMAGE) $$DISK; \
	    else \
	        sudo dd if=$(CUSTOM_IMAGE) of=$$DISK bs=16M oflag=direct status=progress conv=fsync; \
	    fi'
	sudo sync
	@echo ""
	@echo "==> Done. Insert SD into Pi, connect ethernet, power on."
	@echo "    Watch firstboot progress (after ~30 s):"
	@echo "      ssh $(PI_USER)@$(PI_HOSTNAME).local 'journalctl -u wpa3-firstboot -f'"
	@echo "    When complete:"
	@echo "      make deploy PI=$(PI_HOSTNAME).local"

clean_image:
	rm -f $(CUSTOM_IMAGE)
	@echo "Base image cache kept in run/cache/. Remove manually if needed."

ssh_first:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	@if [ ! -f "$(SSH_KEY)" ]; then \
		echo "Generating SSH key ($(SSH_KEY))..."; \
		ssh-keygen -t rsa -b 4096 -f $(HOME)/.ssh/id_rsa -N ""; \
	fi
	@echo "==> Copying SSH key to $(PI_USER)@$(PI)... (you will need to enter the password ONE last time)"
	ssh-copy-id -o StrictHostKeyChecking=no -i $(SSH_KEY) $(PI_USER)@$(PI)
	@echo "==> Done! You can now log in without a password: make ssh"
