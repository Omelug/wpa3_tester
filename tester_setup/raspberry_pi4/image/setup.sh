#!/usr/bin/env bash
# Non-internet Pi setup - called from firstboot.sh and bootstrap.sh (as root)
# Usage: setup.sh [path-to-cmdline.txt]   default: /boot/firmware/cmdline.txt
set -euo pipefail

CMDLINE=${1:-/boot/firmware/cmdline.txt}

# cmdline.txt - idempotent strip then append
sed -i 's/ earlyprintk//g;
        s/ xhci_hcd\.quirks=[^ ]*//g;
        s/ usbcore\.autosuspend=-\?[0-9]*//g' "$CMDLINE"
sed -i 's/$/ earlyprintk xhci_hcd.quirks=270336 usbcore.autosuspend=-1/' "$CMDLINE"
update-initramfs -u

# modprobe.d
printf 'options ath9k_hw ani_enable=0\noptions ath9k_htc user_regd=1\noptions ath9k user_regd=1\n' \
    > /etc/modprobe.d/ath9k.conf
printf 'options rtw88_core disable_lps_deep=y debug_mask=0xff\noptions rtw88_usb disable_lps_deep=y\n' \
    > /etc/modprobe.d/rtw88.conf
printf 'options rtw89_core disable_lps_deep=y debug_mask=0xff\noptions rtw89_usb disable_lps_deep=y\n' \
    > /etc/modprobe.d/rtw89.conf
echo "options mt76_usb disable_usb_sg=1" > /etc/modprobe.d/mt76.conf

# static IPs on eth0
nmcli connection show eth0-static &>/dev/null || \
    nmcli connection add type ethernet ifname eth0 con-name eth0-static
nmcli connection modify eth0-static \
    ipv4.method manual \
    ipv4.addresses "10.0.0.2/24,192.168.0.2/24,192.168.1.100/24" \
    ipv4.gateway "10.0.0.1" \
    ipv4.dns "8.8.8.8,1.1.1.1"
nmcli connection up eth0-static 2>/dev/null || true

# WiFi region CZ
raspi-config nonint do_wifi_country CZ

# SSH key from boot partition (placed there by customize.sh)
BOOT_KEY=/boot/firmware/authorized_key.pub
if [ -f "$BOOT_KEY" ]; then
    PI_USER=$(getent passwd 1000 | cut -d: -f1)
    PI_HOME=$(getent passwd 1000 | cut -d: -f6)
    mkdir -p "$PI_HOME/.ssh"
    cp "$BOOT_KEY" "$PI_HOME/.ssh/authorized_keys"
    chmod 700 "$PI_HOME/.ssh"
    chmod 600 "$PI_HOME/.ssh/authorized_keys"
    chown -R "${PI_USER}:${PI_USER}" "$PI_HOME/.ssh"
fi
