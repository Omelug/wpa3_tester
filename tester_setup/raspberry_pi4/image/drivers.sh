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

_dkms_install "rtw88"     "https://github.com/lwfinger/rtw88"            /tmp/rtw88-src
#_dkms_install "8188gu"    "https://github.com/morrownr/8188gu"           /tmp/8188gu-src
_dkms_install "8821cu"    "https://github.com/morrownr/8821cu-20210916"  /tmp/8821cu-src
_dkms_install "rtl8852au" "https://github.com/WimLee115/rtl8852au-build" /tmp/rtl8852au-src
