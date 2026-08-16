#!/usr/bin/env bash
# Runs once on the Pi's first boot (via wpa3-firstboot.service).
# Installs build dependencies and configures the environment.
# Progress visible via: journalctl -u wpa3-firstboot -f
set -euo pipefail

DONE_FLAG=/var/lib/wpa3-firstboot.done
[ -f "$DONE_FLAG" ] && exit 0

echo "[firstboot] Starting at $(date)"

# --- Build dependencies
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential cmake ninja-build ccache tshark tcpdump \
    clang lld mold pkg-config flex bison git g++-14 \
    libssl-dev \
    libnl-3-dev libnl-genl-3-dev libnl-route-3-dev \
    libpcap-dev \
    libssh-dev \
    libyaml-cpp-dev \
    libtins-dev \
    iproute2 iw tcpdump iptables socat dnsmasq \
    libgeoip-dev liburcu-dev libcli-dev libsodium-dev libnet1-dev \
    libcurl4-openssl-dev \
    usb-modeswitch usb-modeswitch-data \
    avahi-daemon quilt \
    dkms "linux-headers-$(uname -r)"

source /usr/local/bin/wpa3-drivers.sh

echo "[firstboot] Building mausezahn from source..."
git clone --depth=1 https://github.com/netsniff-ng/netsniff-ng /tmp/netsniff-ng
(cd /tmp/netsniff-ng && ./configure && make mausezahn && make install_mausezahn)
rm -rf /tmp/netsniff-ng

echo "[firstboot] Building hostapd-mana from source..."
git clone --depth=1 https://gitlab.com/kalilinux/packages/hostapd-mana /tmp/hostapd-mana
(
    cd /tmp/hostapd-mana
    QUILT_PATCHES=debian/patches quilt push -a
    cd hostapd
    make "-j$(nproc)"
    install -m 755 hostapd     /usr/sbin/hostapd-mana
    install -m 755 hostapd_cli /usr/sbin/hostapd-mana_cli
    mkdir -p /etc/hostapd-mana
    cp hostapd.conf     /etc/hostapd-mana/hostapd-mana.conf
    cp hostapd.eap_user /etc/hostapd-mana/hostapd-mana.eap_user
    install -m 644 debian/certs/* /etc/hostapd-mana/ 2>/dev/null || true
)
rm -rf /tmp/hostapd-mana

chmod +x /usr/bin/dumpcap

# RTL8188GU: switch from USB CD-ROM mode (0bda:1a2b) to WiFi mode on plug-in
cat > /etc/usb_modeswitch.d/0bda:1a2b << 'EOF'
DefaultVendor=0x0bda
DefaultProduct=0x1a2b
TargetVendor=0x0bda
TargetProduct=0xb711
StandardEject=1
CheckSuccess=20
EOF

# -- WiFi region
#TODO hardcoded region
raspi-config nonint do_wifi_country CZ

# --- SSH key
# /boot/firmware is where RPi OS Bookworm mounts the FAT boot partition
BOOT_KEY=/boot/firmware/authorized_key.pub
if [ -f "$BOOT_KEY" ]; then
    # uid 1000 is the primary user created from userconf.txt
    PI_USER=$(getent passwd 1000 | cut -d: -f1)
    PI_HOME=$(getent passwd 1000 | cut -d: -f6)
    mkdir -p "$PI_HOME/.ssh"
    cp "$BOOT_KEY" "$PI_HOME/.ssh/authorized_keys"
    chmod 700 "$PI_HOME/.ssh"
    chmod 600 "$PI_HOME/.ssh/authorized_keys"
    chown -R "${PI_USER}:${PI_USER}" "$PI_HOME/.ssh"
    echo "[firstboot] SSH key installed for $PI_USER"
fi

# --- Done
touch "$DONE_FLAG"
systemctl disable wpa3-firstboot.service
echo "[firstboot] Complete at $(date)"
