# Raspberry Pi 4B 

Target OS: **Raspberry Pi OS Lite 64-bit (Bookworm)**
 #TODO zkontrolovat, 6e 
! on kernel 6.6 

- WiFi interfaces are unmanaged by NetworkManager
- ethernet stays managed and needed for communication (SSH, DHCP, internet sharing ).

---

## Automated image (recommended)

##### Build image:  ```make image```

After download, it customize image: 
- creates user `pi` / `wpa3tester`
- enables SSH
- injects `~/.ssh/id_rsa.pub` for key-based login
- sets hostname `wpa3-tester`
- disables NetworkManager for all `wlan*` interfaces
- installs a firstboot service that runs `apt install` on first boot

Override defaults if needed: (check [Makefile](Makefile) for more options)

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

### Flash to SD card 
!!! This will overwrite your disk, check 
```bash
make flash DISK=/dev/sdX
```

Lists available block devices and asks for confirmation before writing.

### Notebook ethernet setup (direct cable only)

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
# Replace `wlan0` with your internet interface 
sudo iptables -t nat -A POSTROUTING -o wlan0  -j MASQUERADE
# Replace`eth0` with the cable interface.
sudo iptables -A FORWARD -i eth0 -j ACCEPT
sudo iptables -A FORWARD -o eth0 -j ACCEPT
```

### First boot

Insert SD card, connect ethernet cable, power on, `make internet`'.
The firstboot service installs build dependencies (~3 min).
Follow progress via IP (works immediately, no mDNS needed):

```bash
ssh pi@10.0.0.2 'journalctl -u wpa3-firstboot -f'
```

When it prints `[firstboot] Complete` the Pi is ready.

### Deploy & run

```bash
# Push source and build on Pi
make deploy PI=10.0.0.2

# Deploy + launch tester
make run PI=10.0.0.2

# Custom config
make run PI=10.0.0.2 CONFIG=wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml
```

---

## Manual setup (stock image fallback)

1. Flash **Raspberry Pi OS Lite (64-bit)** via `rpi-imager`
   - Advanced settings: enable SSH, set username/password
2. Boot, connect ethernet
3. Run bootstrap: `make bootstrap PI=<ip-address>`

Then proceed with `make deploy` / `make run` as above.

> `bootstrap.sh` also disables USB autosuspend and ath9k_hw ANI — for stability

---

## Cross-compilation (fast iteration, build on host)

Instead of building on the Pi, compile for `aarch64` on the host and push only
the binary

1. One-time host dependencies `sudo apt install clang lld gcc-aarch64-linux-gnu g++-aarch64-linux-gnu`

2. Sync sysroot from Pi: 
Pull Pi's libraries to `cross-sysroot/` (repeat after `apt install` on Pi):
 <br> `make sysroot PI=10.0.0.2`

3. Build and deploy `make deploy-cross PI=10.0.0.2`

4. Run `make run PI=10.0.0.2`

5. Cleanup `make clean_cross`   # remove build-cross/ directory

### Remote debugging (CLion)

Host requirement: `sudo apt install gdb-multiarch` 

1. Start gdbserver on Pi:
   ```make run-debug PI=10.0.0.2```

2. In CLion select **"Pi: GDB debug"** and click Debug —
   automatically runs `make deploy-cross` then connects to `10.0.0.2:1234`.


   If the config doesn't load: *Run > Edit Configurations > + > GDB Remote Debug*,
   set symbol file to `build-cross/bin/wpa3_tester`, host `10.0.0.2`, port `1234`,
   GDB path `gdb-multiarch`.

