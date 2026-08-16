#!/usr/bin/env bash
# Shared DKMS driver installation — sourced by firstboot.sh and bootstrap.sh.
# To add/remove a driver, edit only this file.
set -euo pipefail

_dkms_install() {
    local label=$1 url=$2 tmp=$3
    echo "==> Installing ${label} driver (DKMS)..."
    sudo rm -rf "${tmp}"
    sudo GIT_TERMINAL_PROMPT=0 git clone "${url}" "${tmp}"
    local PKG VER
    PKG=$(sed -n 's/^PACKAGE_NAME="\(.*\)"/\1/p' "${tmp}/dkms.conf")
    VER=$(sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' "${tmp}/dkms.conf")
    if [ ! -d "/usr/src/${PKG}-${VER}" ]; then
        sudo mv "${tmp}" "/usr/src/${PKG}-${VER}"
    else
        sudo rm -rf "${tmp}"
    fi
    sudo dkms add     -m "${PKG}" -v "${VER}" 2>/dev/null || true
    sudo dkms install -m "${PKG}" -v "${VER}" 2>/dev/null || true
}

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

_dkms_install "rtw88"     "https://github.com/lwfinger/rtw88"            /tmp/rtw88-src
#_dkms_install "8188gu"    "https://github.com/morrownr/8188gu"           /tmp/8188gu-src
_dkms_install "8821cu"    "https://github.com/morrownr/8821cu-20210916"  /tmp/8821cu-src
_dkms_install "rtl8852au" "https://github.com/WimLee115/rtl8852au-build" /tmp/rtl8852au-src
