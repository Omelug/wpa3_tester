## wpa3_tester

<!-- TODO change line height -->

Automatization of Wi-Fi attack testing.
The main goal of this tester is make everything what can be automated, automatic.
Get as many important logs, as possible and don't show useless messages.
Project was build like implementation part of bachelor thesis. #TODO link to pdf  

In this file is only general info for whole project, for specific topic:
- setup issues (read it, important) [setup_issues.md](tester_setup/setup_issues.md)
- TODO list is in [TODO.txt](doc/TODO.txt)
- Supported attacks: [attacks.md](doc/wpa3_tester_doc/attacks/attacks.md)
- Development: [development.md](doc/wpa3_tester_doc/development/development.md) (check for adding new test/test suite)
- check other files in [wpa3_tester_doc](doc/wpa3_tester_doc)

### Usage:
- most of the program needs sudo, should be required, but for sure...
- `make run_release` - compile & run (`make run` for debug version) 
- [attack_config](wpa3_test/attack_config) - folder for config attacks
- `make help`
- check Makefile for more info
- dont run multiple instances at once 

### Results
results of test are stored in [data](data) folder
(same trees as [attack_config](wpa3_test/attack_config), but separated to test_data / suite_data).

`make make_overview` for show of collected data on HTMl page

### Tester setup

Raspberry 4b - can be run from laptop on raspberry (connected on ethernet), check [raspberry README.md](tester_setup/raspberry_pi4/README.md) (raspberry kernel can be compiled and setup like .img)


## Known issues:
-  usb hub dont work with bl0ck attacks (mt76x2u second adapter didnt load)