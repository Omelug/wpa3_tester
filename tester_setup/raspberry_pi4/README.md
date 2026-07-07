# Raspberry Pi 4B — setup & deploy

Target OS: **Raspberry Pi OS Lite 64-bit (Bookworm)**

WiFi interfaces are unmanaged by NetworkManager — the tester controls them
directly via nl80211. Ethernet stays managed (SSH, DHCP).

---

## A) Automated image (recommended)

### 1. Build image

```bash
make image
```

Downloads Raspberry Pi OS Lite, customizes it:
- creates user `pi` / `wpa3tester`
- enables SSH
- injects `~/.ssh/id_rsa.pub` for key-based login
- sets hostname `wpa3-tester`
- disables NetworkManager for all `wlan*` interfaces
- installs a firstboot service that runs `apt install` on first boot

Override defaults if needed:

```bash
make image PI_USER=pi PI_PASSWORD=secret PI_HOSTNAME=wpa3-tester SSH_KEY=~/.ssh/id_ed25519.pub
```

#### Static IP (recommended)

Without `PI_IP` the Pi uses DHCP and the address may change between boots.
Set a static IP to always reach the Pi on the same address:

```bash
# Home network (router as gateway)
make image PI_IP=192.168.1.100 PI_GW=192.168.1.1

# Direct cable PC ↔ Pi (no router, no gateway needed)
make image PI_IP=10.0.0.2
```

For a direct cable connection, set the PC's ethernet port to `10.0.0.1/24`
(once, via NM or `sudo ip addr add 10.0.0.1/24 dev eth0`).
Then deploy with `PI=10.0.0.2` instead of the hostname.

### 2. Flash to SD card

```bash
make flash DISK=/dev/sdX
```

Lists available block devices and asks for confirmation before writing.

### 3. Notebook ethernet setup (direct cable only)

Set the notebook's ethernet interface to the same subnet as `PI_IP` once
(persistent NM profile, survives reboot):

```bash
# Find interface names: internet (e.g. wlan0) and Pi cable (e.g. enp3s0)
ip route show default
ip link show

# Persistent static IP on the cable interface via NetworkManager
sudo nmcli connection add \
  type ethernet ifname enp3s0 con-name pi-direct \
  ipv4.method manual ipv4.addresses 10.0.0.1/24 \
  ipv6.method disabled
sudo nmcli connection up pi-direct
```

#### Internet sharing (required for firstboot apt install)

The Pi has no router — the notebook must NAT its internet connection to the Pi.
Run once per notebook session (not persistent across reboots):

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o wlan0  -j MASQUERADE
sudo iptables -A FORWARD -i enp3s0 -j ACCEPT
sudo iptables -A FORWARD -o enp3s0 -j ACCEPT
```

> Replace `wlan0` with your internet interface and `enp3s0` with the cable interface.

> **`.local` hostname** (`wpa3-tester.local`) requires `avahi-daemon` and
> `libnss-mdns` on the notebook:
> ```bash
> sudo apt install avahi-daemon libnss-mdns
> ```
> Until firstboot completes, `.local` won't resolve — use the IP directly.

### 4. First boot

Insert SD card, connect ethernet cable, power on.
The firstboot service installs build dependencies (~3 min).
Follow progress via IP (works immediately, no mDNS needed):

```bash
ssh pi@10.0.0.2 'journalctl -u wpa3-firstboot -f'
```

When it prints `[firstboot] Complete` the Pi is ready.

### 5. Deploy & run

```bash
# Push source and build on Pi
make deploy PI=10.0.0.2

# Deploy + launch tester
make run PI=10.0.0.2

# Custom config
make run PI=10.0.0.2 CONFIG=wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml
```

`make deploy` rsyncs the project source (excluding `build/`, `data/`, `.git/`)
and rebuilds on the Pi. Typical iteration time: rsync + build.

---

## B) Manual setup (stock image fallback)

1. Flash **Raspberry Pi OS Lite (64-bit)** via `rpi-imager`
   - Advanced settings: enable SSH, set username/password
2. Boot, connect ethernet
3. Run bootstrap:

```bash
make bootstrap PI=<ip-address>
```

Then proceed with `make deploy` / `make run` as above.

---
