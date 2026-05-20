### Cache
- for faster check are some data cached

#### HWInfo cache (Actor_Config)
- HW info is part of Actor_Config params
- key is {permanent_mac, driver_name, driver_hash, module_hash}

#### two_iface 
- cache results of two_iface tests (active_test, injection_* tests)
- these test are run directly like another RunStatus test → slow
- run in cache folder
- if you will run this test manually,  cache will be not used