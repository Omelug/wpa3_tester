#!/usr/bin/env bash
# Runs once on the Pi's first boot (via wpa3-firstboot.service).
# Progress visible via: journalctl -u wpa3-firstboot -f
set -euo pipefail

DONE_FLAG=/var/lib/wpa3-firstboot.done
[ -f "$DONE_FLAG" ] && exit 0

echo "[firstboot] Starting at $(date)"

bash /usr/local/bin/wpa3-setup.sh

# --- Build dependencies (internet required)
source /usr/local/bin/wpa3-packages.sh
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y "${WPA3_APT_PACKAGES[@]}"

KVER=$(uname -r)
if ! find "/lib/modules/${KVER}/updates" -iname '*.ko*' 2>/dev/null | grep -q .; then
    echo "[firstboot] WARNING: no pre-baked WiFi driver modules found - run 'make image' with a custom kernel"
fi

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

# post-package setup (fish and dumpcap must be installed first)
chmod +x /usr/bin/dumpcap
chsh -s /usr/bin/fish "$(getent passwd 1000 | cut -d: -f1)"

touch "$DONE_FLAG"
systemctl disable wpa3-firstboot.service
echo "[firstboot] Complete at $(date) - rebooting for cmdline.txt changes"
reboot
