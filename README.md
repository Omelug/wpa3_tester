## wpa3_tester

The main goal of this tester is make everything what can be automated, automatic.
Get as many important logs, as possible and dont show useless logs. 

In this file are only general info for whole project, for specific classes check [wpa3_tester_doc](doc/wpa3_tester_doc).

### Supported attacks
- TODO

### Code culture
- [attacks](wpa3_test/src/attacks), [attack_config](wpa3_test/attack_config) and [tests](tests) have same folder structure 

#### Scan configs
- some "tests" are ony scans (but logic is same, so there are in attack_config)

#### How to add new attack?
- strictly recommended add wrapper first when PoC is available
- add code to [src](wpa3_test/src), header to  [include](wpa3_test/include)
- add [attack_config](wpa3_test/attack_config) (add schema.yaml if you want) //TODO link to config desctiotion
- add  attack functions to [attacks.h](wpa3_test/include/attacks/attacks.h)


### Tests

#### Test hardware
- test hardware is in [test_hardware](doc/test_hardware)
- TODO add scan_test to generate 
#### tests
- in [tests](tests) folder are doctest unit tests
- they should pass any time, without connected hardware 

#### Manual tests
- in manual test are test what cant be run without user interaction or hardware connection (USB interfaces, routers)
- 2
