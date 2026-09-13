### Code culture

This folder describe only possibilities what needs code change.
If you don't need change code, only attacks configs, check [Test.md](../Test.md) / [TestSuite.md](../TestSuite.md).

- [attacks](../../../wpa3_test/src/attacks), [attack_config](../../../wpa3_test/attack_config)
  and [tests](../../../tests) have same folder structure

You can change some default paths/names before compilation in  [default.h](../../../wpa3_test/include/default.h)
(Should be auto changed everywhere, except of doc folder).

### Structure decisions

- I use JetBrains IDE Clion, so if you want easy setup, use it as well, run configs and dictionaries are part
  of [.idea](../../../.idea)
- I created plugin for link test paths. #TODOlink to forgejo / add mirror ton github
- I try to write all in english, but some //TODO are in czech, sorry

### Development FAQ

#### How to add new observer?

- add code to [observer .cpp files](../../../wpa3_test/src/observer), headers
  to [observer headers](../../../wpa3_test/include/observer)
- add validation to [test_validator.schema.yaml](../../../wpa3_test/attack_config/validator/test_validator.schema.yaml)
  with [observer specific validator](../../../wpa3_test/attack_config/validator/programs/observer)
- optionally add showcase of observer render functions to [observer](../../../result_overview/src/observer)

#### How to add new attack?

- strictly recommended add wrapper first when PoC is available
- add code to [src](../../../wpa3_test/src), header to  [include](../../../wpa3_test/include)
- add [attack_config](../../../wpa3_test/attack_config) (add schema.yaml if you want) , written in custom yaml
  format [yaml_validation.md](../yaml_validation.md)
- add attack functions to [attacks.h](../../../wpa3_test/include/attacks/attacks.h)
- *optionaly*: add entry to visualization into [headers](../../../wpa3_test/include/visual)
  and [sources](../../../wpa3_test/src/visual)

DISCLAIMER: if you want parse packets, in project are libpcap nad libtins, libtins have some horrible behaviour.
Add parsing with libpcap first, libtins only for simplification what can be tested (libtins library can be helpful, but
sometimes it is Trojan horse)

#### How to add new suite?

- for better suite parsing is typical add result.json as result into tests in filler
- add config to [attack_config](../../../wpa3_test/attack_config) with ```config_type: test_suite ```
- check Test suite types in [TestSuite.md](../TestSuite.md)
- Test suite setup/test_report
    - set suite_function key and register it in [test_suites.h](../../../wpa3_test/include/visual/test_suites.h)
    - add code for setup/test_report to  [include/visual](../../../wpa3_test/include/visual)
