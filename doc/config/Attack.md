### Attack:
Attack is configured by config in folder [attack_config](../../wpa3_test/attack_config) \
Attacker file format is defined in [test_validator.yaml](../../wpa3_test/attack_config/validator/test_validator.yaml) with json schema. 
specific json schema validator for attack_config can be set in attack_config/validator 

Config: \
attacker_module: specify name for find setup/run functions in [attacks.cpp](../../wpa3_test/src/attacks/attacks.cpp) \
actors: Test needs at least one actor. ( see [Actor.md](./Actor.md))
    - during [setup.cpp](../../wpa3_test/src/setup/setup.cpp) are interfaces found for each actor
attack_config: config specified for attack 

#### Run one attack test:
Test for one attack can be run with one config file:
```c++
sudo ./build/bin/wpa3_tester --config wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml 
```

<!-- TODO test list -->


config:
    create run status
    check interface resources
check requirements:
    change interfaces config/namespaces
setup:
    start actors (and logging)
    start observers
    start pcap logging
run:
    run attacks
    log
statistic:
    get gata from log
    create graphs
    create report for run

    