# Raspberry Pi 4B 

Target OS: RPI_IMAGE_URL in [Makefile](Makefile)
(Default 6.18.39+rpt-rpi-v8)

- WiFi interfaces are unmanaged by NetworkManager
- ethernet (eth0) managed and needed for communication (SSH, DHCP, internet sharing)

---

## Build image:
 ```make image```[<-](mk/image.mk)

It download and customizes image: 
- add to [kernel](mk/kernel.mk) wifi debug before compilation, allows in kernel drivers 
- creates user `pi` with password `wpa3tester`
- enables SSH
- injects `~/.ssh/id_rsa.pub` for key-based login (can be run `make ssh_first` later if not working )
- sets hostname `wpa3-tester`
- disables NetworkManager for all `wlan*` interfaces
- installs a firstboot service that runs `apt install` on first boot

Override defaults if needed: (check start of [Makefile](Makefile) for more options)

```bash
 make image PI_USER=pi PI_PASSWORD=secret PI_HOSTNAME=wpa3-tester SSH_KEY=~/.ssh/id_ed25519.pub
```

#### Static IP (recommended)
Without `PI_IP` the Pi uses DHCP and the address may change between boots.
Set a static IP to always reach the Pi on the same address:

```bash
# Direct cable PC <-> Pi (no router, no gateway needed)
make image PI_IP=10.0.0.2
```

For a direct cable connection, set the PC's ethernet port to `10.0.0.1/24`
(once, via NM or `sudo ip addr add 10.0.0.1/24 dev eth0`).
Then deploy with `PI=10.0.0.2` instead of the hostname.

##### Notebook ethernet setup (direct cable only)

```bash
# find interface names: internet
ip route show default
ip link show

# persistent static IP on the cable interface via NetworkManager
sudo nmcli connection add \
  type ethernet ifname enp3s0 con-name pi-direct \
  ipv4.method manual ipv4.addresses 10.0.0.1/24 \
  ipv6.method disabled
sudo nmcli connection up pi-direct
```

### Flash to SD card 
!!! This will overwrite your disk, check carefully correct names before
```bash
make flash DISK=/dev/sdX
```

Lists available block devices and asks for confirmation before writing.



#### Internet sharing (required for firstboot apt install)

The Pi has no router - the notebook must NAT its internet connection to the Pi.
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

### Results

```make results ``` - get results to tester_setup/raspberry_pi4/run/html

-----


## Cross-compilation (fast iteration, build on host)

Instead of building on the Pi, compile for `aarch64` on the host and push only
the binary

- One-time host dependencies `sudo apt install clang lld gcc-aarch64-linux-gnu g++-aarch64-linux-gnu`
- Sync sysroot from Pi:
   Pull Pi's libraries to `run/cross-sysroot/` (repeat after `apt install` on Pi):
   <br> `make sysroot PI=10.0.0.2`

- Build and deploy `make deploy-cross PI=10.0.0.2`

- Run `make run PI=10.0.0.2`
- Cleanup `make clean_cross`   # remove build-cross/ directory


### Deploy & run

```bash
# push source and build on Pi (only if need whole build on raspberry!)
make deploy PI=10.0.0.2

# cross-deploy + launch tester
make run PI=10.0.0.2 TEST_SUITE=wpa_downgrade_filler

# Custom config
make run PI=10.0.0.2 CONFIG=wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml
```

### Remote debugging (CLion)
- start gdbserver on Pi:  ```make run_debug TEST_SUITE=CSA_Dlink_external_filler``` (run on tester laptop)
- if you use CLion, select **raspberry** and click Debug - connects to `10.0.0.2:1234`.
- manually: 
    ```
    gdb-multiarch tester_setup/raspberry_pi4/run/build-cross/bin/wpa3_tester
    (gdb) set sysroot tester_setup/raspberry_pi4/run/cross-sysroot
    (gdb) set substitute-path /pi/wpa3_tester/ ./
    (gdb) target remote 10.0.0.2:1234
    (gdb) continue
    ```