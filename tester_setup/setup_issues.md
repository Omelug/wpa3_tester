
### Disable Network manager
in  /etc/NetworkManager/conf.d/99-unmanaged-wifi.conf

### Regulatory domains
- ignore_interfaces are name specific - so you need same names after restart 
- ignore_interfaces are for example f=ro internet connection
How hard link mac to name on debian : 
```sudo vim /etc/systemd/network/10-internal-wifi.link```

```
[Match]
MACAddress=aa:bb:cc:dd:ee:ff

[Link]
Name=wlan0
```

sudo udevadm control --reload
sudo update-initramfs -u
