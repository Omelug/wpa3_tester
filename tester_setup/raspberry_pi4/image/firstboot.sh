#!/usr/bin/env bash
# Runs once on the Pi's first boot (via wpa3-firstboot.service).
# Installs build dependencies and configures the environment.
# Progress visible via: journalctl -u wpa3-firstboot -f
set -euo pipefail

DONE_FLAG=/var/lib/wpa3-firstboot.done
[ -f "$DONE_FLAG" ] && exit 0

echo "[firstboot] Starting at $(date)"

# ── Build dependencies ─────────────────────────────────────────────────────────
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential cmake ninja-build ccache \
    clang lld pkg-config flex bison git \
    libssl-dev \
    libnl-3-dev libnl-genl-3-dev \
    libpcap-dev \
    libssh-dev \
    libyaml-cpp-dev \
    libtins-dev \
    iproute2 iw tcpdump \
    avahi-daemon

# ── WiFi region ────────────────────────────────────────────────────────────────
raspi-config nonint do_wifi_country CZ

# ── mDNS — enables reach via hostname.local ────────────────────────────────────
systemctl enable avahi-daemon
systemctl start  avahi-daemon

# ── SSH key — injected into boot partition by customize.sh ─────────────────────
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

# ── Passwordless sudo (dev/test machine only) ──────────────────────────────────
PI_USER=$(getent passwd 1000 | cut -d: -f1)
echo "${PI_USER} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/90-wpa3-dev
chmod 440 /etc/sudoers.d/90-wpa3-dev

# ── Done ───────────────────────────────────────────────────────────────────────
touch "$DONE_FLAG"
systemctl disable wpa3-firstboot.service
echo "[firstboot] Complete at $(date)"
