
## Actor_config 
- object with one process, one interface
- ActorPtr is wrapper (use this, except of tests)

## Observer
- object for one process
- ObserverPtr is wrapper (use this, except of tests)

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