### Wifi injection

- most of information are from https://github.com/vanhoefm/wifi-injection
- injection - possibility to send raw PDU
- some packets are overwritten  by kernel, some with hardware/devices
- radiotap has NOSEQ and ORDER TXFlags to not change seq and ORDER of fragments
- kernel changes can be tested with one interface (selftest), but it cant detect devices/hardware overwrite

#### More Fragments
TODO přepast
- some network cards (Intel AC-3160 and those based on the RT5572 chipset) have issue with injecting fragments with the More Fragments (MF) flag set.
- solved by workaround - after injecting the frame with the MF flag set, 
immediately injecting a dummy frame without the MF flag.
- With the RT5572 chipset, this dummy frame must also have the same QoS TID as the injected frame, but all other fields did not matter
