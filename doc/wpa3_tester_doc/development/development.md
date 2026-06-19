### Code culture

This folder describe only possibilities what needs code change.
If you dont need change code, only config, check [Test.md](../Test.md) / [TestSuite.md](../TestSuite.md).

- [attacks](../../../wpa3_test/src/attacks), [attack_config](../../../wpa3_test/attack_config) and [tests](../../../tests) have same folder structure

#### How to add new attack?

- strictly recommended add wrapper first when PoC is available
- add code to [src](../../../wpa3_test/src), header to  [include](../../../wpa3_test/include)
- add [attack_config](../../../wpa3_test/attack_config) (add schema.yaml if you want) //TODO link to config description
- add  attack functions to [attacks.h](../../../wpa3_test/include/attacks/attacks.h)

DISCLAIMER: if you want parse packets, in project are libpcap nad libtins, libtins have some horrible behaviour.
Add parsing with libpcap first, libtins only for simplification what can be tested (libtins library can be helpful, but sometimes it is Trojan horse)

#### How to add new suite?

- for better suite parsing is typical add result.json as result into tests in filler
- add config to [attack_config](../../../wpa3_test/attack_config) with ```config_type: test_suite ```
- check Test suite types in [TestSuite.md](../TestSuite.md)
- Test suite setup/test_report
  - set suite_function key and register it in [test_suites.h](../../../wpa3_test/include/suite/test_suites.h)
  - add code for setup/test_report to  [include/suite](../../../wpa3_test/include/suite) and [src/suite](../../../wpa3_test/src/suite)
