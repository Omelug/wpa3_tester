GDB_VER         := $(shell gdb --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
GDBSERVER_CACHE := run/cache/gdbserver-$(GDB_VER)-aarch64
GDB_PORT        ?= 1234

.PHONY: sysroot deploy-cross test-cross clean_cross gdbserver-build gdbserver-start

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

# ── Cross-compile + deploy binary ─────────────────────────────────────────────
# Requires on host (one-time):
#   sudo apt install clang lld gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

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
	$(SSH) "mkdir -p $(REMOTE)/build/bin $(REMOTE)/wpa3_test"
	rsync -az --info=progress2 \
		$(CROSS_BUILD)/bin/wpa3_tester \
		$(PI_USER)@$(PI):$(REMOTE)/build/bin/wpa3_tester
	rsync -az --delete --info=progress2 \
		$(SRC_ROOT)/wpa3_test/attack_config/ \
		$(PI_USER)@$(PI):$(REMOTE)/wpa3_test/attack_config/
	@echo "==> Binary deployed. Run: make run"

# ── Cross-compile + run all tests on Pi ───────────────────────────────────────

test-cross:
	@test -n "$(PI)" || { echo "Error: PI not set"; exit 1; }
	@test -d "$(SYSROOT)" || { echo "Error: sysroot missing — run 'make sysroot' first"; exit 1; }
	PKG_CONFIG_SYSROOT_DIR=$(SYSROOT) \
	PKG_CONFIG_PATH=$(SYSROOT)/usr/lib/aarch64-linux-gnu/pkgconfig:$(SYSROOT)/usr/share/pkgconfig \
	cmake -S $(SRC_ROOT) -B $(CROSS_BUILD) -G Ninja \
		-DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DCMAKE_SYSROOT=$(SYSROOT) \
		-DCMAKE_BUILD_TYPE=Debug \
		-DWPA3_PROJECT_ROOT=$(REMOTE_ABS)/wpa3_test
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

# ── gdbserver cross-build (cached) ────────────────────────────────────────────
# Compiled once per host GDB version; cached in run/cache/gdbserver-<ver>-aarch64.

$(GDBSERVER_CACHE):
	@echo "==> Cross-compiling gdbserver $(GDB_VER) for aarch64 (one-time)..."
	@test -n "$(GDB_VER)" || { echo "ERROR: gdb not found on host"; exit 1; }
	sudo apt-get install -y gcc-aarch64-linux-gnu libexpat1-dev texinfo
	mkdir -p run/cache run/gdb-build
	curl -fsSL "https://ftp.gnu.org/gnu/gdb/gdb-$(GDB_VER).tar.xz" \
	    | tar xJ -C run/gdb-build --strip-components=1
	mkdir -p run/gdb-build/build
	cd run/gdb-build/build && ../configure \
	    --host=aarch64-linux-gnu \
	    --prefix=/usr/local \
	    CC=aarch64-linux-gnu-gcc \
	    CFLAGS="-O2 -static" \
	    --enable-gdbserver \
	    --disable-gdb \
	    --disable-inprocess-agent --disable-nls
	$(MAKE) -C run/gdb-build/build -j$(shell nproc)
	find run/gdb-build/build -maxdepth 3 -name gdbserver -type f -executable \
	    -exec cp {} $(GDBSERVER_CACHE) \;
	rm -rf run/gdb-build
	@echo "==> Cached: $(GDBSERVER_CACHE)"

gdbserver-build: $(GDBSERVER_CACHE)

gdbserver-start: $(GDBSERVER_CACHE)
	$(SSH) "sudo pkill gdbserver 2>/dev/null || true"
	scp $(GDBSERVER_CACHE) $(PI_USER)@$(PI):/home/pi/gdbserver
	$(SSH) "chmod +x /home/pi/gdbserver"
	$(SSH) "nohup /home/pi/gdbserver :$(GDB_PORT) $(REMOTE)/build/bin/wpa3_tester --config $(REMOTE)/$(CONFIG) </dev/null > /tmp/gdbserver.log 2>&1 &"
	@sleep 1
	$(SSH) "pgrep -x gdbserver > /dev/null || { echo 'ERROR: gdbserver failed to start:'; cat /tmp/gdbserver.log; exit 1; }"
	@echo "==> gdbserver $(GDB_VER) running on $(PI):$(GDB_PORT)"
