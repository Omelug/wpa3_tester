## Test / Test suite

### Finding of test

### Tester_Config
- tester have config in [global_config.yaml](../../wpa3_test/attack_config/global_config.yaml)

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

### Test suites
- have tbe in format [test_suite_validator.schema.yaml](../../wpa3_test/attack_config/validator/test_suite_validator.schema.yaml)
- config_type: test_suite
- path/generatros
#### generators 
- var_ like prefix for placeholder
- more described in schema
- config generating to  {rss.run_folder}/test_config/<generator_name>