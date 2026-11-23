
.PHONY: tools dragondrain hostapd_vuln openssl_1_1_1w

TOOLS_SRC        := $(CURDIR)/run/tools-src
TOOLS_BUILD      := $(CURDIR)/run/tools-build

DRAGONDRAIN_SRC   := $(TOOLS_SRC)/dragondrain-and-time
DRAGONDRAIN_BUILD := $(TOOLS_BUILD)/dragondrain-and-time
DRAGONDRAIN_REPO  := https://github.com/vanhoefm/dragondrain-and-time

HOSTAPD_VULN_SRC  := $(TOOLS_SRC)/hostapd-vuln
OPENSSL_VULN_SRC  := $(TOOLS_SRC)/openssl-vuln
OPENSSL_1_1_1W    := $(TOOLS_BUILD)/openssl-1.1.1w
HOSTAPD_2_6_BIN   := $(TOOLS_BUILD)/hostapd_2_6_OpenSSL_1_1_1w

HOSTAPD_VULN_REPO := https://git.w1.fi/hostap.git
OPENSSL_VULN_REPO := https://github.com/openssl/openssl.git

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

openssl_1_1_1w:
	@[ -d $(OPENSSL_VULN_SRC) ] || \
	    git clone --branch OpenSSL_1_1_1w --depth=1 $(OPENSSL_VULN_REPO) $(OPENSSL_VULN_SRC)
	@[ -f $(OPENSSL_1_1_1W)/lib/libcrypto.a ] || \
	    /run/current-system/sw/bin/nix-shell $(CURDIR)/shell.nix --run \
	    "cd $(OPENSSL_VULN_SRC) && \
	    ./Configure linux-aarch64 \
	        --prefix=$(OPENSSL_1_1_1W) \
	        --cross-compile-prefix=aarch64-unknown-linux-gnu- \
	        no-shared no-asm && \
	    make -j$(shell nproc) build_libs && \
	    mkdir -p $(OPENSSL_1_1_1W)/lib $(OPENSSL_1_1_1W)/include && \
	    cp libcrypto.a libssl.a $(OPENSSL_1_1_1W)/lib/ && \
	    cp -r include/openssl $(OPENSSL_1_1_1W)/include/"

# Cross-compile vulnerable hostapd 2.6 against static OpenSSL 1.1.1w for aarch64.
# PKG_CONFIG_PATH='' prevents the system OpenSSL 3.x headers from leaking in via
# pkg-config --cflags (Debian returns -I/usr/include which beats EXTRA_CFLAGS on the Pi).
# Deployed to tools/hostapd/hostapd_2_6_OpenSSL_1_1_1w; get_hostapd_with_openssl() finds
# it on the first run and skips the on-Pi compilation entirely.
hostapd_vuln: openssl_1_1_1w
	@test -n "$(PI)"      || { echo "Error: PI not set"; exit 1; }
	@test -d "$(SYSROOT)" || { echo "Error: sysroot missing - run 'make sysroot' first"; exit 1; }
	@[ -d $(HOSTAPD_VULN_SRC) ] || \
	    git clone --branch hostap_2_6 --depth=1 $(HOSTAPD_VULN_REPO) $(HOSTAPD_VULN_SRC)
	@[ -f $(HOSTAPD_2_6_BIN) ] || \
	    /run/current-system/sw/bin/nix-shell $(CURDIR)/shell.nix --run \
	    "cd $(HOSTAPD_VULN_SRC)/hostapd && \
	    cp defconfig .config && \
	    printf '\nCONFIG_LIBNL32=y\nCONFIG_IEEE80211W=y\nCONFIG_SAE=y\nCONFIG_WNM=y\nCONFIG_OCV=y\nCONFIG_OWE=y\nCONFIG_SUITEB192=y\nCONFIG_DPP=y\nCONFIG_IEEE80211N=y\nCONFIG_IEEE80211AC=y\nCONFIG_IEEE80211AX=y\nCONFIG_IEEE80211R=y\nCONFIG_INTERWORKING=y\nCONFIG_TESTING_OPTIONS=y\nCONFIG_CTRL_IFACE=y\nCONFIG_DEBUG_FILE=y\nCONFIG_EAP_PWD=y\n' >> .config && \
	    make clean && \
	    PKG_CONFIG_PATH='' \
	    make -j$(shell nproc) \
	        CC=aarch64-unknown-linux-gnu-gcc \
	        EXTRA_CFLAGS='-DALL_DH_GROUPS -I$(OPENSSL_1_1_1W)/include -include $(OPENSSL_1_1_1W)/include/openssl/asn1.h -I$(SYSROOT)/usr/include/libnl3 --sysroot=$(SYSROOT)' \
	        LDFLAGS='-L$(OPENSSL_1_1_1W)/lib --sysroot=$(SYSROOT) -L$(SYSROOT)/usr/lib/aarch64-linux-gnu -L$(SYSROOT)/lib/aarch64-linux-gnu' && \
	    mkdir -p $(TOOLS_BUILD) && cp hostapd $(HOSTAPD_2_6_BIN)"
	/run/current-system/sw/bin/nix-shell $(CURDIR)/shell.nix --run \
	    "patchelf --set-interpreter /lib/ld-linux-aarch64.so.1 $(HOSTAPD_2_6_BIN)"
	$(SSH) "mkdir -p $(REMOTE_ABS)/tools/hostapd"
	$(RSYNC) -az $(HOSTAPD_2_6_BIN) \
	    $(PI_USER)@$(PI):$(REMOTE_ABS)/tools/hostapd/hostapd_2_6_OpenSSL_1_1_1w
	@echo "==> hostapd 2.6 (OpenSSL 1.1.1w) -> $(REMOTE_ABS)/tools/hostapd/"

tools: dragondrain hostapd_vuln
	@echo "==> All tools deployed"
