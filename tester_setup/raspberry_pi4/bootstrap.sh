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
    iproute2 iw tcpdump iptables socat dnsmasq fish \
    libcurl4-openssl-dev \
    usb-modeswitch usb-modeswitch-data \
    libgeoip-dev liburcu-dev libcli-dev libsodium-dev libnet1-dev \
    quilt \
    dkms "linux-headers-$(uname -r)"

#echo "==> Installing hcxtools from source (latest git)..."
#sudo rm -rf /tmp/hcxtools
#git clone --depth=1 https://github.com/ZerBea/hcxtools.git /tmp/hcxtools
#(cd /tmp/hcxtools && make && sudo make install)
#sudo rm -rf /tmp/hcxtools

if ! command -v mausezahn &>/dev/null; then
    echo "==> Building mausezahn from source (not in RPi OS repos)..."
    sudo rm -rf /tmp/netsniff-ng
    git clone --depth=1 https://github.com/netsniff-ng/netsniff-ng /tmp/netsniff-ng
    (cd /tmp/netsniff-ng && sudo ./configure && sudo make mausezahn && sudo make install_mausezahn)
    sudo rm -rf /tmp/netsniff-ng
fi
#TODO musí tam být defaultně (spíč jo)
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

source /tmp/wpa3-drivers.sh

sudo chmod +x /usr/bin/dumpcap

echo "==> Configuring ath9k: disable ANI, enable user regulatory domain override..."
printf 'options ath9k_hw ani_enable=0\noptions ath9k_htc user_regd=1\noptions ath9k user_regd=1\n' \
    | sudo tee /etc/modprobe.d/ath9k.conf > /dev/null
echo "==> Disabling USB autosuspend..."
echo "options usbcore autosuspend=-1" | sudo tee /etc/modprobe.d/usbcore.conf > /dev/null
echo "==> Configuring rtw88 (disable deep power save, enable debug logging)..."
printf 'options rtw88_core disable_lps_deep=y debug_mask=0xff\noptions rtw88_usb disable_lps_deep=y\n' \
    | sudo tee /etc/modprobe.d/rtw88.conf > /dev/null
echo "==> Configuring rtw89 (disable deep power save, enable debug logging)..."
printf 'options rtw89_core disable_lps_deep=y debug_mask=0xff\noptions rtw89_usb disable_lps_deep=y\n' \
    | sudo tee /etc/modprobe.d/rtw89.conf > /dev/null
echo "==> Disabling mt76 USB scatter-gather (https://github.com/morrownr/7612u)..."
echo "options mt76_usb disable_usb_sg=1" | sudo tee /etc/modprobe.d/mt76_usb.conf > /dev/null
echo "==> Disabling USB 3.0 (reduces 2.4 GHz interference)..."
grep -qxF "dtoverlay=disable-usb3" /boot/firmware/config.txt \
    || echo "dtoverlay=disable-usb3" | sudo tee -a /boot/firmware/config.txt > /dev/null
sudo update-initramfs -u

echo "==> Setting WiFi region CZ..." # TODO hardcoded change
sudo raspi-config nonint do_wifi_country CZ

echo "==> Configuring passwordless sudo for $USER (dev/test machine)..."
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/90-wpa3-dev > /dev/null
sudo chmod 440 /etc/sudoers.d/90-wpa3-dev

echo "==> Enabling IP forwarding + NAT (wlan* -> eth0 for dnsmasq clients)..."
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/10-ip-forward.conf > /dev/null
sudo sysctl -p /etc/sysctl.d/10-ip-forward.conf

sudo tee /usr/local/sbin/wpa3-nat.sh << 'EOF' > /dev/null
#!/usr/bin/env bash
/usr/sbin/iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || \
    /usr/sbin/iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
/usr/sbin/iptables -C FORWARD -i wlan+ -o eth0 -j ACCEPT 2>/dev/null || \
    /usr/sbin/iptables -A FORWARD -i wlan+ -o eth0 -j ACCEPT
/usr/sbin/iptables -C FORWARD -o wlan+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    /usr/sbin/iptables -A FORWARD -o wlan+ -m state --state RELATED,ESTABLISHED -j ACCEPT
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

echo "==> Configuring static IPs on eth0 (10.0.0.2 + 192.168.0.2)..."
# Modify or create the eth0 NM connection with both static addresses
if sudo nmcli connection show eth0-static &>/dev/null; then
    sudo nmcli connection modify eth0-static \
        ipv4.method manual \
        ipv4.addresses "10.0.0.2/24,192.168.0.2/24" \
        ipv4.gateway "10.0.0.1" \
        ipv4.dns "8.8.8.8,1.1.1.1"
else
    sudo nmcli connection add type ethernet ifname eth0 con-name eth0-static \
        ipv4.method manual \
        ipv4.addresses "10.0.0.2/24,192.168.0.2/24" \
        ipv4.gateway "10.0.0.1" \
        ipv4.dns "8.8.8.8,1.1.1.1"
fi
# Note: not calling 'nmcli connection up' here to avoid dropping the SSH session

PI_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "==> Bootstrap complete."
echo "    Next step on host machine:"
echo "    make deploy PI=${PI_IP}"
