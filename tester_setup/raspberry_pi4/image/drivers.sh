#!/usr/bin/env bash
# Shared DKMS driver installation - sourced by firstboot.sh and bootstrap.sh.
# To add/remove a driver, edit only this file.
set -euo pipefail

_dkms_install() {
    local label=$1 url=$2 tmp=$3 extra_cflags=${4:-}
    echo "==> Installing ${label} driver (DKMS)..."
    sudo rm -rf "${tmp}"
    sudo GIT_TERMINAL_PROMPT=0 git clone "${url}" "${tmp}"
    # append EXTRA_CFLAGS at end of Makefile - works for any driver using #ifdef CONFIG_*
    [ -n "${extra_cflags}" ] && echo "EXTRA_CFLAGS += ${extra_cflags}" | sudo tee -a "${tmp}/Makefile" > /dev/null
    local PKG VER
    PKG=$(sed -n 's/^PACKAGE_NAME="\(.*\)"/\1/p' "${tmp}/dkms.conf")
    VER=$(sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' "${tmp}/dkms.conf")
    if dkms status -m "${PKG}" -v "${VER}" 2>/dev/null | grep -q "installed"; then
        echo "==> ${label} already installed, skipping"
        sudo rm -rf "${tmp}"
        return 0
    fi
    if [ ! -d "/usr/src/${PKG}-${VER}" ]; then
        sudo mv "${tmp}" "/usr/src/${PKG}-${VER}"
    else
        sudo rm -rf "${tmp}"
    fi
    sudo dkms add     -m "${PKG}" -v "${VER}" 2>/dev/null || true
    sudo dkms install -m "${PKG}" -v "${VER}" 2>/dev/null || true

    # Verify the module(s) DKMS just built actually match the running kernel
    # (DKMS reports "installed" even when it silently built against the wrong)
    local KVER_RUNNING BUILD_DIR KO KVER_BUILT BAD=0
    KVER_RUNNING=$(uname -r)
    BUILD_DIR="/var/lib/dkms/${PKG}/${VER}/${KVER_RUNNING}/aarch64/module"
    for KO in "${BUILD_DIR}"/*.ko*; do
        [ -e "${KO}" ] || continue
        KVER_BUILT=$(modinfo "${KO}" 2>/dev/null | sed -n 's/^vermagic:[[:space:]]*\([^ ]*\).*/\1/p')
        if [ -n "${KVER_BUILT}" ] && [ "${KVER_BUILT}" != "${KVER_RUNNING}" ]; then
            echo "!! ${label}: built module ($(basename "${KO}")) vermagic '${KVER_BUILT}' != running kernel '${KVER_RUNNING}'"
            BAD=1
        fi
    done
    if [ "${BAD}" -eq 1 ]; then
        echo "!! ${label}: DKMS built against mismatched headers - removing the bad build."
        sudo dkms remove -m "${PKG}" -v "${VER}" -k "${KVER_RUNNING}" 2>/dev/null || true
        return 1
    fi
}

echo "==> Blacklisting rtl8192cu (buggy EAPOL delivery) in favour of rtl8xxxu, works with rtl88"
echo "blacklist rtl8192cu" | sudo tee /etc/modprobe.d/blacklist-rtl8192cu.conf > /dev/null

echo "==> Configuring usb_modeswitch for RTL8188GU..."
sudo mkdir -p /etc/usb_modeswitch.d

sudo tee /etc/usb_modeswitch.d/0bda:1a2b > /dev/null << 'EOF'
DefaultVendor=0x0bda
DefaultProduct=0x1a2b
TargetVendor=0x0bda
TargetProduct=0xb711
StandardEject=1
CheckSuccess=20
EOF

sudo tee /etc/udev/rules.d/40-rtl8188gu.rules > /dev/null << 'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ATTR{idProduct}=="1a2b", RUN+="/usr/sbin/usb_modeswitch '%k'"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger

#TODO fix versions
_dkms_install "rtw88"     "https://github.com/lwfinger/rtw88"            /tmp/rtw88-src \
    "-DCONFIG_RTW88_DEBUGFS -DCONFIG_RTW88_DEBUG" \
    || echo "!! rtw88 driver install failed - see messages above"
_dkms_install "8188gu"    "https://github.com/morrownr/8188gu"           /tmp/8188gu-src
_dkms_install "8821cu"    "https://github.com/morrownr/8821cu-20210916"  /tmp/8821cu-src \
    || echo "!! 8821cu driver install failed - see messages above"
_dkms_install "rtl8852au" "https://github.com/WimLee115/rtl8852au-build" /tmp/rtl8852au-src \
    "-DCONFIG_RTW89_DEBUGFS -DCONFIG_RTW89_8852AU -DCONFIG_RTW89_DEBUG" \
    || echo "!! rtl8852au driver install failed - see messages above"