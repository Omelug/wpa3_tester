### Actor_config

- object with one process, one interface
- ActorPtr is wrapper (use this, except of tests)
- some hardware capabilities links for change Actor_Config status are in [ActorCofig_iface_func.cpp](../../wpa3_test/src/system/ActorCofig_iface_func.cpp)
- have subclasses Actor_Config with suffixes [_sim](../../../wpa3_test/src/config/Actor_Config/Actor_Config_sim.cpp), [_internal](../../../wpa3_test/src/config/Actor_Config/Actor_Config_internal.cpp), [_external](../../../wpa3_test/src/config/Actor_Config/Actor_Config_external.cpp)

#### add new param to Actor_Config?

- needs to be only convertable to string/bool (it needed for easy backtracking fuctions)
- add param to SK/BK list
- edit SK_NAMES, BK_NAMES strings!
- if should not be saved in str_vals/bool_vals:
  - add `private` param
  - edit operator[](SK/BK key) (set param)
  - edit operator[](SK/BK key) const (get param)

### Observer

- object for one process
- ObserverPtr is wrapper (use this, except of tests)
- observer static format functions are in file [observers.cpp](../../wpa3_test/src/observer/observers.cpp)
- wrappers in folder are in [observer](../../../wpa3_test/src/observer)

### RunStatus

- object for status of [test](../Test.md)
- created by config
- small info around module functions()
- process manager, actors, observers
- is executed with `execute()` function.

-- TODO add image from PDF

### RunSuiteStatus

- status for [test_suites](../TestSuite.md)
- generate test configs
- add paths to test_paths
- in `execute()` run tests linear in
