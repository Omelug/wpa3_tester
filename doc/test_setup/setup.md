### Routers
If you dont have clue how setup IP, try check my testing hardware config in 
[test_hardware](../test_hardware) or check https://dd-wrt.com for default settings. 

### USB
- USB 3 is on 2,4 Ghz 
https://openwrt.org/docs/guide-user/network/wifi/usb3.0-wifi-issues

For debian try to disable usb 3: (this disables it globally, persistent)
(check [bootstrap.sh](../../tester_setup/raspberry_pi4/bootstrap.sh))

sudo nano /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash xhci_hcd.quirks=270336"
sudo update-grub

