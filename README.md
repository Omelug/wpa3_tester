## wpa3_tester

<!-- TODO change line height -->

Automatization of wifi attack testing.
The main goal of this tester is make everything what can be automated, automatic.
Get as many important logs, as possible and dont show useless messages.

In this file are only general info for whole project, for specific classes check [wpa3_tester_doc](doc/wpa3_tester_doc). 

Supported attacks: [attacks.md](doc/wpa3_tester_doc/attacks/attacks.md)

Development: [development.md](doc/wpa3_tester_doc/development/development.md) (check for adding new test/ test suite)

Usage:
- most of program needs sudo, should be required, but for sure...
- `make compile` - compile & run 
- [attack_config](wpa3_test/attack_config) - folder for config attacks
- `make help` for check  (`make run` for example)
- check Makefile for more info

`make make_overview` for show of collected data in page 

#### Weird things of the code

- if are connected 2 mt76x2u interfaces (90:de:80:6c:90:92, //TODO ) kernel do in some tests weird thing,
  it stop all network programs (NetworkManager) and I have to reboot for check even dmesg, so don't do that.
  maybe some too many open files bug, but it's terrible for debugging
