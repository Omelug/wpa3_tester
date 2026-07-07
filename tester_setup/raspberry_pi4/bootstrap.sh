#!/usr/bin/env bash
# First-time setup for Raspberry Pi 4B running Raspberry Pi OS Lite (64-bit / Debian Bookworm).
# Run via: make bootstrap PI=<address>
set -euo pipefail

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
    iproute2 iw tcpdump

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
