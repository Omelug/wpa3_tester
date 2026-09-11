## Raspberry
- raspbian iso - Linux 6.18.44-v8+ aarch64
- customize image with [customize.sh](../../tester_setup/raspberry_pi4/image/customize.sh)
- firstboot (run once after first boot [firstboot.sh](../../tester_setup/raspberry_pi4/image/firstboot.sh))
- bootsrap for other changes during run [bootstrap.sh](../../tester_setup/raspberry_pi4/bootstrap.sh)
- some  [drivers.sh](../../tester_setup/raspberry_pi4/image/drivers.sh)

make image download raspbian and add dome flags for debugging in [debug.config](../../tester_setup/raspberry_pi4/kernel/debug.config)

TODO - physical setup (add photo/schema)

requires on host (one-time):
`sudo apt install clang lld gcc-aarch64-linux-gnu g++-aarch64-linux-gnu`

### run
use test suite at the start of [deploy.mk](../../tester_setup/raspberry_pi4/mk/deploy.mk)

`make run`
`make run_debug` - run gdbserver, can connect to in with Clion "raspberry" target

## USB issues:

With multiple adapters, raspberry can be unstable and end in [usb_helper.cpp](../../../wpa3_test/src/setup/usb_helper.cpp)
(Ok, I ma not sure now, it maybe only because I used bad adapter for usb hub) #FIXME try

```
[25188.466800] usb usb2-port1: over-current change #9105
[25188.619190] usb 1-1-port4: over-current change #8941
[25188.674797] usb usb2-port2: over-current change #9105
[25188.835245] usb 1-1-port1: over-current change #8936
```