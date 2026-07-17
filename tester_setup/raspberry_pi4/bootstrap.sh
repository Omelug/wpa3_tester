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
    clang lld mold pkg-config flex bison git \
    libssl-dev \
    libnl-3-dev libnl-genl-3-dev libnl-route-3-dev \
    libpcap-dev \
    libssh-dev \
    libyaml-cpp-dev \
    libtins-dev \
    iproute2 iw tcpdump \
    libcurl4-openssl-dev \
    usb-modeswitch usb-modeswitch-data \
    libgeoip-dev liburcu-dev libcli-dev libsodium-dev libnet1-dev \
    quilt \
    dkms linux-headers-$(uname -r)

echo "==> Installing hcxtools from source (latest git)..."
sudo rm -rf /tmp/hcxtools
git clone --depth=1 https://github.com/ZerBea/hcxtools.git /tmp/hcxtools
(cd /tmp/hcxtools && make && sudo make install)
sudo rm -rf /tmp/hcxtools

if ! command -v mausezahn &>/dev/null; then
    echo "==> Building mausezahn from source (not in RPi OS repos)..."
    sudo rm -rf /tmp/netsniff-ng
    git clone --depth=1 https://github.com/netsniff-ng/netsniff-ng /tmp/netsniff-ng
    (cd /tmp/netsniff-ng && sudo ./configure && sudo make mausezahn && sudo make install_mausezahn)
    sudo rm -rf /tmp/netsniff-ng
fi

if ! command -v hostapd-mana &>/dev/null; then
    echo "==> Building hostapd-mana from source..."
    sudo rm -rf /tmp/hostapd-mana
    git clone --depth=1 https://gitlab.com/kalilinux/packages/hostapd-mana /tmp/hostapd-mana
    (
        cd /tmp/hostapd-mana
        QUILT_PATCHES=debian/patches quilt push -a
        cd hostapd
        make -j$(nproc)
        sudo install -m 755 hostapd     /usr/sbin/hostapd-mana
        sudo install -m 755 hostapd_cli /usr/sbin/hostapd-mana_cli
        sudo mkdir -p /etc/hostapd-mana
        sudo cp hostapd.conf     /etc/hostapd-mana/hostapd-mana.conf
        sudo cp hostapd.eap_user /etc/hostapd-mana/hostapd-mana.eap_user
        sudo install -m 644 ../debian/certs/* /etc/hostapd-mana/ 2>/dev/null || true
    )
    sudo rm -rf /tmp/hostapd-mana
fi

dkms_install() {
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
    sudo dkms add    -m "${PKG}" -v "${VER}" 2>/dev/null || true
    sudo dkms install -m "${PKG}" -v "${VER}" 2>/dev/null || true
}

dkms_install "rtw88"  "https://github.com/lwfinger/rtw88"  /tmp/rtw88-src
#dkms_install "8188gu" "https://github.com/morrownr/8188gu" /tmp/8188gu-src

sudo chmod +x /usr/bin/dumpcap

echo "==> Adding RTL8188GU USB modeswitch rule..."
sudo tee /etc/usb_modeswitch.d/0bda:1a2b << 'EOF' > /dev/null
DefaultVendor=0x0bda
DefaultProduct=0x1a2b
StandardEject=1
EOF

echo "==> Disabling ath9k_hw ANI for driver stability..."
echo "options ath9k_hw ani_enable=0" | sudo tee /etc/modprobe.d/ath9k.conf > /dev/null
echo "==> Disabling USB autosuspend..."
echo "options usbcore autosuspend=-1" | sudo tee /etc/modprobe.d/usbcore.conf > /dev/null
sudo update-initramfs -u

echo "==> Setting WiFi region CZ..." # TODO hardcoded change
sudo raspi-config nonint do_wifi_country CZ

echo "==> Configuring passwordless sudo for $USER (dev/test machine)..."
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/90-wpa3-dev > /dev/null
sudo chmod 440 /etc/sudoers.d/90-wpa3-dev

PI_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "==> Bootstrap complete."
echo "    Next step on host machine:"
echo "    make deploy PI=${PI_IP}"
