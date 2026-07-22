#!/usr/bin/env bash
# Customizes a Raspberry Pi OS Lite (64-bit, Bookworm) image for wpa3-tester.
# Must be run as root
# Args: <image.img> <user> <password> <hostname> <ssh_pubkey_path>

set -euo pipefail

IMAGE=$1
PI_USER=$2
PI_PASSWORD=$3
PI_HOSTNAME=$4
SSH_KEY=${5:-}
PI_IP=${6:-}
PI_GW=${7:-}
PI_PREFIX=${8:-24}

SCRIPT_DIR=$(dirname "$(realpath "$0")")

echo "==> Attaching loop device to $IMAGE ..."
LOOP=$(losetup --find --show --partscan "$IMAGE")
echo "    $LOOP"

BOOT=$(mktemp -d)
ROOT=$(mktemp -d)

# ---  cleanup on error/exit (even if Ctrl+C is pressed)
cleanup() {
    umount "$BOOT" 2>/dev/null || true
    umount "$ROOT" 2>/dev/null || true
    losetup -d "$LOOP" 2>/dev/null || true
    rmdir "$BOOT" "$ROOT" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Mounting partitions..."
mount "${LOOP}p1" "$BOOT"   # FAT32 boot/firmware partition
mount "${LOOP}p2" "$ROOT"   # ext4 root partition

# ---- Boot partition

# enable SSH on first boot
touch "$BOOT/ssh"

# create user - bookworm reads userconf.txt from boot partition on first boot
PW_HASH=$(echo "$PI_PASSWORD" | openssl passwd -6 -stdin)
echo "${PI_USER}:${PW_HASH}" > "$BOOT/userconf.txt"

# SSH public key — firstboot.sh installs it from this location on the Pi
if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    cp "$SSH_KEY" "$BOOT/authorized_key.pub"
    echo "    SSH key: $SSH_KEY"
else
    echo "    SSH key: not found at '$SSH_KEY' — password login only"
fi

# --- Debug / crash logging

#TODO not tried yet, i dont have 3.3 UART<->USB cable
# UART serial console on GPIO14 (TX) / GPIO15 (RX) — kernel messages go to
# a USB-UART adapter even during a kernel panic
echo "enable_uart=1" >> "$BOOT/config.txt"
# Pstore — saves the panic log into a reserved RAM region that survives a soft
# reboot; after restart the log appears in /sys/fs/pstore/
echo "dtoverlay=pstore" >> "$BOOT/config.txt"
# earlyprintk — emit pre-console kernel messages on the serial line
sed -i 's/$/ earlyprintk/' "$BOOT/cmdline.txt"

# --- Root partition

echo "$PI_HOSTNAME" > "$ROOT/etc/hostname"
# Update /etc/hosts (may not exist in minimal image — ignore failure)
sed -i "s/raspberrypi/$PI_HOSTNAME/g" "$ROOT/etc/hosts" 2>/dev/null || true

# ethernet static IP — create NM connection profile if PI_IP is set
if [ -n "$PI_IP" ]; then
    UUID=$(cat /proc/sys/kernel/random/uuid)
    mkdir -p "$ROOT/etc/NetworkManager/system-connections"
    {
        cat << EOF
[connection]
id=eth0-static
uuid=$UUID
type=ethernet
interface-name=eth0
autoconnect=yes
autoconnect-priority=10

[ethernet]

[ipv4]
method=manual
addresses=$PI_IP/$PI_PREFIX
EOF
        [ -n "$PI_GW" ] && echo "gateway=$PI_GW"
        echo "dns=8.8.8.8;1.1.1.1;"
        printf '\n[ipv6]\nmethod=disabled\n'
    } > "$ROOT/etc/NetworkManager/system-connections/eth0-static.nmconnection"
    # NM ignores connection files that aren't 600
    chmod 600 "$ROOT/etc/NetworkManager/system-connections/eth0-static.nmconnection"
    echo "    static IP: $PI_IP/$PI_PREFIX${PI_GW:+  gw $PI_GW}"
else
    echo "    static IP: DHCP"
fi

# ath9k_hw — disable ANI + let the kernel regulatory domain override EEPROM
printf 'options ath9k_hw ani_enable=0\noptions ath9k_htc user_regd=1\noptions ath9k user_regd=1\n' \
    > "$ROOT/etc/modprobe.d/ath9k.conf"
# USB — disable autosuspend (prevents Wi-Fi adapter disconnects under load)
echo "options usbcore autosuspend=-1" > "$ROOT/etc/modprobe.d/usbcore.conf"

# NetworkManager — leave all WiFi interfaces unmanaged
# tester can control them directly via nl80211, ethernet stays managed for SSH
mkdir -p "$ROOT/etc/NetworkManager/conf.d"
cat > "$ROOT/etc/NetworkManager/conf.d/99-unmanaged-wifi.conf" << 'EOF'
[keyfile]
unmanaged-devices=interface-name:wlan*
EOF

# Region CZ — WiFi regulatory domain + timezone
# TODO hardcoded change
echo "REGDOMAIN=CZ" > "$ROOT/etc/default/crda"
ln -sf /usr/share/zoneinfo/Europe/Prague "$ROOT/etc/localtime"
echo "Europe/Prague" > "$ROOT/etc/timezone"

# Passwordless sudo (dev/test machine only)
echo "${PI_USER} ALL=(ALL) NOPASSWD: ALL" > "$ROOT/etc/sudoers.d/90-wpa3-dev"
chmod 440 "$ROOT/etc/sudoers.d/90-wpa3-dev"

# avahi-daemon — enables hostname.local reachability
mkdir -p "$ROOT/etc/systemd/system/multi-user.target.wants"
ln -sf /lib/systemd/system/avahi-daemon.service \
       "$ROOT/etc/systemd/system/multi-user.target.wants/avahi-daemon.service"

# rfkill — unblock WiFi on every boot (RPi OS soft-blocks it by default)
mkdir -p "$ROOT/etc/systemd/system/multi-user.target.wants"
cat > "$ROOT/etc/systemd/system/rfkill-unblock-wifi.service" << 'EOF'
[Unit]
Description=Unblock WiFi rfkill
After=systemd-rfkill.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/rfkill unblock wifi
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
ln -sf /etc/systemd/system/rfkill-unblock-wifi.service \
       "$ROOT/etc/systemd/system/multi-user.target.wants/rfkill-unblock-wifi.service"

# persistent journal
mkdir -p "$ROOT/etc/systemd/journald.conf.d"
cat > "$ROOT/etc/systemd/journald.conf.d/10-persistent.conf" << 'EOF'
[Journal]
Storage=persistent
EOF

# firstboot script + systemd service
install -m 755 "$SCRIPT_DIR/firstboot.sh"      "$ROOT/usr/local/bin/wpa3-firstboot.sh"
install -m 644 "$SCRIPT_DIR/firstboot.service" "$ROOT/etc/systemd/system/wpa3-firstboot.service"

# Enable service (equivalent to systemctl enable, but without chroot/systemctl)
mkdir -p "$ROOT/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/wpa3-firstboot.service \
       "$ROOT/etc/systemd/system/multi-user.target.wants/wpa3-firstboot.service"

echo ""
echo "==> Image customized:"
echo "    hostname : $PI_HOSTNAME  (reach via $PI_HOSTNAME.local after firstboot)"
echo "    user     : $PI_USER / $PI_PASSWORD"
echo "    ssh key  : ${SSH_KEY:-none}"
