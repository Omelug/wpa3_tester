GDB_PORT        ?= 1234

.PHONY: sysroot deploy-cross test-cross clean_cross

# ── Sysroot sync ───────────────────────────────────────────────────────────────
# One-time pull of Pi headers + libs for cross-compilation.
# Re-run after installing new packages on Pi.

sysroot:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	mkdir -p \
		$(SYSROOT)/usr/include \
		$(SYSROOT)/usr/lib/aarch64-linux-gnu \
		$(SYSROOT)/usr/share/pkgconfig \
		$(SYSROOT)/lib/aarch64-linux-gnu
	rsync -az --info=progress2 $(PI_USER)@$(PI):/usr/include/                $(SYSROOT)/usr/include/
	rsync -az --info=progress2 $(PI_USER)@$(PI):/usr/lib/aarch64-linux-gnu/  $(SYSROOT)/usr/lib/aarch64-linux-gnu/
	rsync -az --info=progress2 $(PI_USER)@$(PI):/lib/aarch64-linux-gnu/      $(SYSROOT)/lib/aarch64-linux-gnu/
	rsync -az --info=progress2 $(PI_USER)@$(PI):/usr/share/pkgconfig/        $(SYSROOT)/usr/share/pkgconfig/
	ln -sf aarch64-linux-gnu/ld-linux-aarch64.so.1 $(SYSROOT)/lib/ld-linux-aarch64.so.1
	@echo "==> Sysroot ready: $(SYSROOT)"

# --- Cross-compile + deploy binary
# cmake flags live in CMakePresets.json (cross-rpi4 preset).
# On NixOS: run inside nix-shell with pkgsCross.aarch64-multiplatform.

deploy-cross:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	@test -d "$(SYSROOT)" || { echo "Error: sysroot missing — run 'make sysroot' first"; exit 1; }
	# allow if needed
	# rm -f $(CROSS_BUILD)/CMakeCache.txt
	cmake -S $(SRC_ROOT) --preset cross-rpi4 -DWPA3_PROJECT_ROOT=$(REMOTE_ABS)/wpa3_test
	cmake --build $(CROSS_BUILD) --target wpa3_tester -j$(shell nproc)
	$(SSH) "mkdir -p $(REMOTE)/build/bin $(REMOTE)/wpa3_test"
	rsync -az --info=progress2 \
		$(CROSS_BUILD)/bin/wpa3_tester \
		$(PI_USER)@$(PI):$(REMOTE)/build/bin/wpa3_tester
	rsync -az --delete --info=progress2 \
		$(SRC_ROOT)/wpa3_test/attack_config/ \
		$(PI_USER)@$(PI):$(REMOTE)/wpa3_test/attack_config/
	@echo "==> Binary deployed. Run: make run"

test-cross:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	@test -d "$(SYSROOT)" || { echo "Error: sysroot missing — run 'make sysroot' first"; exit 1; }
	rm -f $(CROSS_BUILD)/CMakeCache.txt
	cmake -S $(SRC_ROOT) --preset cross-rpi4 -DWPA3_PROJECT_ROOT=$(REMOTE_ABS)/wpa3_test
	cmake --build $(CROSS_BUILD) -j$(shell nproc)
	$(SSH) "mkdir -p $(REMOTE)/build/bin $(REMOTE)/wpa3_test"
	$(SSH) "sudo rm -rf $(REMOTE)/build/tests/setup/config_validation/test_suite/run_out 2>/dev/null; true"
	rsync -az --info=progress2 \
		$(CROSS_BUILD)/bin/ \
		$(PI_USER)@$(PI):$(REMOTE)/build/bin/
	rsync -az --no-group --omit-dir-times --info=progress2 \
		--exclude='run_out/' \
		--include='*/' --include='run_*' \
		--include='*.pcap' --include='*.pcapng' \
		--include='*.yaml' --include='*.hccapx' --include='*.txt' \
		--exclude='*' \
		$(CROSS_BUILD)/tests/ \
		$(PI_USER)@$(PI):$(REMOTE)/build/tests/
	rsync -az --no-group --omit-dir-times --info=progress2 \
		--exclude='run_out/' \
		--include='*/' --include='CTestTestfile.cmake' --exclude='*' \
		$(CROSS_BUILD)/ \
		$(PI_USER)@$(PI):$(REMOTE)/build/
	$(SSH) "find $(REMOTE)/build -name 'CTestTestfile.cmake' \
		-exec sed -i 's|$(CROSS_BUILD)|$(REMOTE_ABS)/build|g' {} +"
	rsync -az --delete --info=progress2 \
		$(SRC_ROOT)/wpa3_test/attack_config/ \
		$(PI_USER)@$(PI):$(REMOTE)/wpa3_test/attack_config/
	rsync -az --info=progress2 \
		$(SRC_ROOT)/wpa3_test/attack_config/validator/ \
		$(PI_USER)@$(PI):$(REMOTE)/build/wpa3_test/attack_config/validator/
	$(SSH) "sudo -E ctest --test-dir $(REMOTE)/build --output-on-failure"

clean_cross:
	rm -rf $(CROSS_BUILD)
