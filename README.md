## wpa3_tester

<!-- TODO change line height -->

The main goal of this \tester is make everything what can be automated, automatic.
Get as many important logs, as possible and dont show useless logs.

In this file are only general info for whole project, for specific classes check [wpa3_tester_doc](doc/wpa3_tester_doc). 

Supported attacks: [attacks.md](doc/wpa3_tester_doc/attacks/attacks.md)

Development: [development.md](doc/wpa3_tester_doc/development/development.md)

Usage: 

#### Weird things of the code

- if are connected 2 mt76x2u interfaces (90:de:80:6c:90:92, ) kernel do in some tests weird thing,
  it stop all network programs (NetworkManager) and I have to reboot for check even dmesg, so dont do that.
  maybe some too many open files bug, but its terrible for debugging
