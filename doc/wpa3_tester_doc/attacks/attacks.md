### Attacks
To get more info about attacks, `make make_overview`, it
will generate basic descriptions in HTML pages, path to index will be printed. 

(After run you have to run `make make_overview` again, it's logically separated from rest of program)

- DoS_hard 
  - [cookie_guzzler](../../../wpa3_test/attack_config/DoS_hard/cookie_guzzler)
  - [memory_omnivore](../../../wpa3_test/attack_config/DoS_hard/memory_omnivore)
  - [PMK_gobbler](../../../wpa3_test/attack_config/DoS_hard/PMK_gobbler)
  - [SAE_DoS_wrapper](../../../wpa3_test/attack_config/DoS_hard/SAE_DoS_wrapper) (TODO check if orchestration works)

- DoS_soft
  - [channel_switch](../../../wpa3_test/attack_config/DoS_soft/channel_switch)
  - [bl0ck](../../../wpa3_test/attack_config/DoS_soft/bl0ck)
  - [malformed_eapol1](../../../wpa3_test/attack_config/DoS_soft/malformed_eapol1)
### Active and injection tests (Two Iface)
- these test are needed to be run before with real (because some drivers lies about compatibility)
- cache is used to not run before very test (for details check [cache.md](../cache.md))
- active and injection are children of [TwoIface](../../../wpa3_test/src/attacks/two_iface/TwoIface.cpp)
  ( in cache id are important keys for finding in cache)
- [two_iface](../../../wpa3_test/src/attacks/two_iface) can be added to test config `requirements/two_iface: <two_iface_key>: [<actor_tx>, <actor_rx>]`
  (check [test_validator.schema.yaml](../../../wpa3_test/attack_config/validator/test_validator.schema.yaml) for two_iface_key)


- [two_iface](../../../wpa3_test/attack_config/two_iface) - to check compatibility and can be get from iface info,
  result use [cache](../cache.md)
    - [active_test](../../../wpa3_test/attack_config/two_iface/active_test) - check active
    - [injection](../../../wpa3_test/attack_config/two_iface/injection) - multiple injection tests, for more info check [hw_cap_injection.md](hw_cap_injection.md)


#### Scan configs
- some "tests" are ony scans (but logic is same, so there are in attack_config)

- [scanner](../../../wpa3_test/attack_config/scanner)
    - [ap_info](../../../wpa3_test/attack_config/scanner/ap_info) - internal scanner scan AP
    - [sta_info](../../../wpa3_test/attack_config/scanner/sta_info) - internal scanner(Ap) scan STAs, what will connect
    - [external_info](../../../wpa3_test/attack_config/scanner/external_info) - scanner scan info possible
    - [iface_info](../../../wpa3_test/attack_config/scanner/iface_info) - info from internal Wi-Fi interface

