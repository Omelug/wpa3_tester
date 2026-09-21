#!/usr/bin/env bash
# First-time setup for Raspberry Pi 4B running Raspberry Pi OS Lite (64-bit / Debian Bookworm).
# Run via: make bootstrap PI=<address>
set -euo pipefail

#TODO napsat o usb switch/napájen9 do [pdf / dokumentace s odkazy
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

echo "==> Installing/updating build dependencies..."
source /tmp/wpa3-packages.sh
#TODO update? sudo apt-get update -qq
sudo apt-get install -y "${WPA3_APT_PACKAGES[@]}"

#TODO musí tam být defaultně? (spíš jo)
if ! command -v hostapd-mana &>/dev/null; then
    echo "==> Building hostapd-mana from source..."
    sudo rm -rf /tmp/hostapd-mana
    git clone --depth=1 https://gitlab.com/kalilinux/packages/hostapd-mana /tmp/hostapd-mana
    (
        cd /tmp/hostapd-mana
        QUILT_PATCHES=debian/patches quilt push -a
        cd hostapd
        make "-j$(nproc)"
        sudo install -m 755 hostapd     /usr/sbin/hostapd-mana
        sudo install -m 755 hostapd_cli /usr/sbin/hostapd-mana_cli
        sudo mkdir -p /etc/hostapd-mana
        sudo cp hostapd.conf     /etc/hostapd-mana/hostapd-mana.conf
        sudo cp hostapd.eap_user /etc/hostapd-mana/hostapd-mana.eap_user
        sudo install -m 644 ../debian/certs/* /etc/hostapd-mana/ 2>/dev/null || true
    )
    sudo rm -rf /tmp/hostapd-mana
fi

sudo bash /tmp/wpa3-setup.sh

echo "==> Configuring passwordless sudo for $USER (dev/test machine)..."
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/90-wpa3-dev > /dev/null
sudo chmod 440 /etc/sudoers.d/90-wpa3-dev

echo "==> Enabling IP forwarding + NAT (wlan* -> eth0 for dnsmasq clients)..."
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/10-ip-forward.conf > /dev/null
sudo sysctl -p /etc/sysctl.d/10-ip-forward.conf

#TODO needed?
sudo tee /usr/local/sbin/wpa3-nat.sh << 'EOF' > /dev/null
#!/usr/bin/env bash
add() { /usr/sbin/iptables "$@" 2>/dev/null || true; }
check_add() { /usr/sbin/iptables -C "$@" 2>/dev/null || /usr/sbin/iptables -A "$@"; }
check_add_nat() { /usr/sbin/iptables -t nat -C "$@" 2>/dev/null || /usr/sbin/iptables -t nat -A "$@"; }

# Masquerade all outgoing on eth0 (covers wlan clients + eth0 subnets like 192.168.1.0/24)
check_add_nat POSTROUTING -o eth0 -j MASQUERADE

# Forward: wlan clients -> internet
check_add FORWARD -i wlan+ -o eth0 -j ACCEPT

# Forward: eth0 subnets (e.g. router at 192.168.1.1) -> internet via eth0
check_add FORWARD -i eth0 -s 192.168.1.0/24 -j ACCEPT

# Return traffic for all forwarded connections
check_add FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
sudo chmod +x /usr/local/sbin/wpa3-nat.sh

sudo tee /etc/systemd/system/wpa3-nat.service << 'EOF' > /dev/null
[Unit]
Description=NAT wlan* -> eth0 for WPA3 tester dnsmasq clients
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/wpa3-nat.sh

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable wpa3-nat.service
sudo systemctl start wpa3-nat.service

sudo chmod +x /usr/bin/dumpcap
sudo chsh -s "$(which fish)" "$USER"
echo "==> Bootstrap complete"

