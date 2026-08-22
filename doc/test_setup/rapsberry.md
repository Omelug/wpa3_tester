## Raspberry
- raspbian iso -  linux 6.6 
- some drivers #TODO mave to in-kernel drivers

make image download raspbian and add dome flags for debugging in [debug.config](../../tester_setup/raspberry_pi4/kernel/debug.config)

TODO - physical setup (add photo/schema)

### run
use test suite at the start of [deploy.mk](../../tester_setup/raspberry_pi4/mk/deploy.mk)

`make run`
`make run_debug` - run gdbserver, can connect to in with Clion "raspberry" target
