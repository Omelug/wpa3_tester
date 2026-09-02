### Tests of tester itself

#### Test hardware

- test hardware is in [test_hardware](../test_hardware)
- TODO add scan_test to generate

#### tests

- in [tests](../../tests) folder are doctest unit tests
- they should pass any time, without connected hardware (only few use hwsim)
-  can be run with `make test`

#### Manual tests

- in folder [tests_manual](../../tests_manual)
- in manual test are test what cant be run without user interaction or hardware connection (USB interfaces, routers)
- manual_config_validation is auto test, but it only check , can be run with `make config_validation`

#### Git workflow test
- `make test` is run [test.yml](../../.github/workflows/test.yml)
- manual_config_validatio is run by [validate_configs.yml](../../.github/workflows/validate_configs.yml)
- [clang_tidy.yml](../../.github/workflows/clang_tidy.yml) check basic code culture

