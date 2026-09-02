#!/usr/bin/env bash
# Runs once on the Pi's first boot (via wpa3-firstboot.service).
# Installs build dependencies and configures the environment.
# Progress visible via: journalctl -u wpa3-firstboot -f
set -euo pipefail

DONE_FLAG=/var/lib/wpa3-firstboot.done
[ -f "$DONE_FLAG" ] && exit 0

echo "[firstboot] Starting at $(date)"

# --- Build dependencies
source /usr/local/bin/wpa3-packages.sh
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y "${WPA3_APT_PACKAGES[@]}"

# symlink headers if kernel minor-bumped ahead of apt Why?
KVER=$(uname -r)
if [ ! -d "/lib/modules/$KVER/build" ]; then
    AVAIL=$(find /usr/src -maxdepth 1 -name "linux-headers-*v8*" -type d | sort -V | tail -1)
    [ -n "$AVAIL" ] && mkdir -p "/lib/modules/$KVER" && ln -sf "$AVAIL" "/lib/modules/$KVER/build"
fi

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

# -- WiFi region
#TODO hardcoded region
raspi-config nonint do_wifi_country CZ

# -- xhci quirks for USB adapter stability (keeps adapters on USB 2 speed)
sed -i 's/ xhci_hcd\.quirks=[0-9]*//' /boot/firmware/cmdline.txt
sed -i 's/$/ xhci_hcd.quirks=270336/' /boot/firmware/cmdline.txt

# --- Secondary IP on eth0 so LAN router (192.168.1.1) is reachable without changing default route
#FIXME hardcoded ip address
nmcli connection modify eth0-static +ipv4.addresses "192.168.1.100/24" 2>/dev/null || true

# --- Default shell: fish
PI_USER_1000=$(getent passwd 1000 | cut -d: -f1)
chsh -s /usr/bin/fish "$PI_USER_1000"

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
