### USB
- USB 3 is on 2,4 Ghz 
https://openwrt.org/docs/guide-user/network/wifi/usb3.0-wifi-issues

For debian try to disable usb 3: (this disables it globally, persistent)

sudo nano /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash xhci_hcd.quirks=270336"
sudo update-grub
