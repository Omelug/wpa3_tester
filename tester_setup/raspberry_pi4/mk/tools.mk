
.PHONY: tools dragondrain

TOOLS_SRC        := $(CURDIR)/run/tools-src
TOOLS_BUILD      := $(CURDIR)/run/tools-build

DRAGONDRAIN_SRC   := $(TOOLS_SRC)/dragondrain-and-time
DRAGONDRAIN_BUILD := $(TOOLS_BUILD)/dragondrain-and-time
DRAGONDRAIN_REPO  := https://github.com/vanhoefm/dragondrain-and-time

# aarch64-linux-gnu- -> aarch64-linux-gnu (strip trailing dash)
CROSS_HOST := $(patsubst %-,%,$(CROSS_COMPILE))

dragondrain:
	@test -n "$(PI)"      || { echo "Error: PI not set"; exit 1; }
	@test -d "$(SYSROOT)" || { echo "Error: sysroot missing - run 'make sysroot' first"; exit 1; }
	@[ -d $(DRAGONDRAIN_SRC) ] || git clone --depth=1 $(DRAGONDRAIN_REPO) $(DRAGONDRAIN_SRC)
	@[ -f $(DRAGONDRAIN_SRC)/config.guess ] || \
	    /run/current-system/sw/bin/nix-shell $(CURDIR)/shell.nix --run \
	    "cd $(DRAGONDRAIN_SRC) && NOCONFIGURE=1 ./autogen.sh"
	mkdir -p $(DRAGONDRAIN_BUILD)
	@[ -f $(DRAGONDRAIN_BUILD)/Makefile ] || \
	    /run/current-system/sw/bin/nix-shell $(CURDIR)/shell.nix --run \
	    "cd $(DRAGONDRAIN_BUILD) && \
	    PKG_CONFIG_PATH='' \
	    PKG_CONFIG_SYSROOT_DIR=$(SYSROOT) \
	    PKG_CONFIG_LIBDIR=$(SYSROOT)/usr/lib/aarch64-linux-gnu/pkgconfig:$(SYSROOT)/usr/share/pkgconfig \
	    $(DRAGONDRAIN_SRC)/configure \
	        --host=$(CROSS_HOST) \
	        CC=$(CROSS_COMPILE)gcc \
	        CXX=$(CROSS_COMPILE)g++ \
	        CFLAGS='--sysroot=$(SYSROOT) -I$(SYSROOT)/usr/include -I$(SYSROOT)/usr/include/aarch64-linux-gnu -fcommon' \
	        LDFLAGS='--sysroot=$(SYSROOT) -L$(SYSROOT)/usr/lib/aarch64-linux-gnu -L$(SYSROOT)/lib/aarch64-linux-gnu -lz -lzstd'"
	@[ -f $(DRAGONDRAIN_BUILD)/src/.libs/dragondrain ] || \
	    /run/current-system/sw/bin/nix-shell $(CURDIR)/shell.nix --run \
	    "$(MAKE) -C $(DRAGONDRAIN_BUILD)/src -j$(shell nproc)"
	/run/current-system/sw/bin/nix-shell $(CURDIR)/shell.nix --run \
	    "patchelf --set-interpreter /lib/ld-linux-aarch64.so.1 \
	              --set-rpath '\$$ORIGIN' \
	              $(DRAGONDRAIN_BUILD)/src/.libs/dragondrain"
	$(SSH) "mkdir -p $(REMOTE_ABS)/tools/dragondrain-and-time/src"
	$(RSYNC) -az $(DRAGONDRAIN_BUILD)/src/.libs/dragondrain \
	    $(PI_USER)@$(PI):$(REMOTE_ABS)/tools/dragondrain-and-time/src/dragondrain
	$(RSYNC) -az $(DRAGONDRAIN_BUILD)/src/aircrack-osdep/.libs/libaircrack-osdep-1.3.0.so \
	    $(PI_USER)@$(PI):$(REMOTE_ABS)/tools/dragondrain-and-time/src/libaircrack-osdep-1.3.0.so
	@echo "==> dragondrain -> $(REMOTE_ABS)/tools/dragondrain-and-time/src/"

tools: dragondrain
	@echo "==> All tools deployed"
