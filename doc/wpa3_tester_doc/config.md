
## Actor_config 
- object with one process, one interface
- ActorPtr is wrapper (use this, except of tests)
- some hardware capabilities links for change Actor_Config status are in [ActorCofig_iface_func.cpp](../../wpa3_test/src/system/ActorCofig_iface_func.cpp)

## Observer
- object for one process
- ObserverPtr is wrapper (use this, except of tests)
- observer static format functions are in file [observers.cpp](../../wpa3_test/src/observer/observers.cpp)
- wrappers in folder are in [observer](../../wpa3_test/src/observer)

### RunStatus
- object for status of test
- created by config
- small info around module functions ()
- process manager, actors, observers
- is executed with `execute()` function.

-- TODO add image from PDF 

### RunSuiteStatus
- status for test suites
- generate test configs
- creates RunStatus for every test