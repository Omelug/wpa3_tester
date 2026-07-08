#!/usr/bin/env bash
# First-time setup for Raspberry Pi 4B running Raspberry Pi OS Lite (64-bit / Debian Bookworm).
# Run via: make bootstrap PI=<address>
set -euo pipefail

echo "==> Checking internet connectivity..."
for i in 1 2 3; do
    curl -fsS --max-time 5 https://deb.debian.org > /dev/null 2>&1 && break
    echo "    Attempt $i/3 failed, retrying in 3s..."
    sleep 3
    if [ $i -eq 3 ]; then
        echo "ERROR: No internet access. On host machine run: make internet PI=$(hostname -I | awk '{print $1}')"
        exit 1
    fi
done

echo "==> Installing build dependencies..."
sudo apt-get update -qq
sudo apt-get install -y \
    build-essential cmake ninja-build ccache \
    clang lld pkg-config flex bison git \
    libssl-dev \
    libnl-3-dev libnl-genl-3-dev \
    libpcap-dev \
    libssh-dev \
    libyaml-cpp-dev \
    libtins-dev \
    iproute2 iw tcpdump \
    dkms linux-headers-$(uname -r)

echo "==> Installing rtw88 driver (DKMS)..."
sudo rm -rf /tmp/rtw88-src
sudo git clone https://github.com/lwfinger/rtw88 /tmp/rtw88-src
PKG=$(sed -n 's/^PACKAGE_NAME="\(.*\)"/\1/p' /tmp/rtw88-src/dkms.conf)
VER=$(sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' /tmp/rtw88-src/dkms.conf)
if [ ! -d "/usr/src/${PKG}-${VER}" ]; then
    sudo mv /tmp/rtw88-src /usr/src/${PKG}-${VER}
else
    sudo rm -rf /tmp/rtw88-src
fi
sudo dkms add -m "${PKG}" -v "${VER}" 2>/dev/null || true
sudo dkms install -m "${PKG}" -v "${VER}" 2>/dev/null || true

echo "==> Setting WiFi region CZ..."
sudo raspi-config nonint do_wifi_country CZ

echo "==> Configuring passwordless sudo for $USER (dev/test machine)..."
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/90-wpa3-dev > /dev/null
sudo chmod 440 /etc/sudoers.d/90-wpa3-dev

PI_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "==> Bootstrap complete."
echo "    Next step on host machine:"
echo "    make deploy PI=${PI_IP}"
