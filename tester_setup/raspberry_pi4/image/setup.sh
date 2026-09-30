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
printf 'options ath9k_hw ani_enable=0 debug=0xffffffff\noptions ath9k_htc user_regd=1 debug=0xffffffff\noptions ath9k user_regd=1 debug=0xffffffff\n' \
    > /etc/modprobe.d/ath9k.conf
printf 'options rtw88_core disable_lps_deep=y debug_mask=0xff\noptions rtw88_usb disable_lps_deep=y\n' \
    > /etc/modprobe.d/rtw88.conf
printf 'options rtw89_core disable_lps_deep=y debug_mask=0xff\noptions rtw89_usb disable_lps_deep=y\n' \
    > /etc/modprobe.d/rtw89.conf
printf 'options mt76_usb disable_usb_sg=1\n# blacklist + install: belt-and-suspenders to suppress in-kernel mt76x2u/mt76x2e\n# (shadowed by mt76x2u_git/mt76x2e_git from updates/; symbol CRC mismatch otherwise)\nblacklist mt76x2u\nblacklist mt76x2e\ninstall mt76x2u /bin/false\ninstall mt76x2e /bin/false\n' \
    > /etc/modprobe.d/mt76.conf
# rtl8xxxu handles RTL8192CU; staging rtl8192cu has known EAPOL delivery bug
echo "blacklist rtl8192cu" > /etc/modprobe.d/blacklist-rtl8192cu.conf

# static IPs on eth0
nmcli connection show eth0-static &>/dev/null || \
    nmcli connection add type ethernet ifname eth0 con-name eth0-static
nmcli connection modify eth0-static \
    ipv4.method manual \
    ipv4.addresses "10.0.0.2/24,192.168.0.2/24,192.168.1.100/24" \
    ipv4.gateway "10.0.0.1" \
    ipv4.dns "8.8.8.8,1.1.1.1"
nmcli connection up eth0-static 2>/dev/null || true

# usb_modeswitch - RTL8188GU: CDROM mode (0bda:1a2b) -> WiFi mode (0bda:b711)
mkdir -p /etc/usb_modeswitch.d
cat > /etc/usb_modeswitch.d/0bda:1a2b << 'EOF'
DefaultVendor=0x0bda
DefaultProduct=0x1a2b
TargetVendor=0x0bda
TargetProduct=0x8832
StandardEject=1
CheckSuccess=20
EOF
cat > /etc/udev/rules.d/40-rtl8188gu.rules << 'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ATTR{idProduct}=="1a2b", RUN+="/lib/udev/usb_modeswitch '/%k'"
EOF
udevadm control --reload-rules 2>/dev/null || true

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
