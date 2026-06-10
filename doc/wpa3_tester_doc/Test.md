## Test / Test suite
- in [global_config.yaml](../../wpa3_test/attack_config/global_config.yaml) 
are paths for external programs, link to path of external whitebox actors etc.
### Finding of test

### Run_Config
- test_suite_only
  - delete_old (false/true) - delete old tests before run 
  - test_report (false/true) - should tests in suite generate reports
- test/test_suites (global false values are rewritten first by test_suite and by test config after)
  - rewrite (false/errors/all) - 
  - compile_external (false/true) - compilation of external programs
  - install_req (false/true)  - install external programs

if not compile_external/install_req and something have to be compilated/installed → req_err

### Test
- defined by a YAML configuration file. 

All tests must pass validation through the main [validator](../../wpa3_test/attack_config/validator/test_validator.schema.yaml).

### Software Requirements for the Test:
In the validator, requirement program for main test machine have to be in list `actors/<actor_name>/setup/requirements`
  (doesn't matter what actor, only for clear config)

These requirements will be installed before execution if `install_req: true` is set.
For some programs `compile_external: true` is needed for auto install.
Otherwise, the system will return a req_error if not already installed.
Some programs need folder config in [global_config](../../wpa3_test/attack_config/global_config.yaml).

External:
The OpenWrt program has its own specific configuration for requirements, check [openwrt_validator](../../wpa3_test/attack_config/validator/programs/actor/openwrt.yaml).

### Active and injection tests (TwoIface)
- these test are needed to be run before with real (because some drivers lies about compatibility)
- cache is used to not run before very test (for details check [cache.md](cache.md))
- active and injection are children of [TwoIface](../../wpa3_test/src/attacks/two_iface/TwoIface.cpp) 
( in cache id are important keys for finding in cache)
- [two_iface](../../wpa3_test/src/attacks/two_iface) can be added to test config `requirements/two_iface: <two_iface_key>: [<actor_tx>, <actor_rx>]`
  (check [test_validator.schema.yaml](../../wpa3_test/attack_config/validator/test_validator.schema.yaml) for two_iface_key)