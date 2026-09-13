Connection to external actor can be part
of [Actor_config.cpp](../../../wpa3_test/src/config/Actor_Config/Actor_config.cpp) (ActorConfig\->conn)

- can be registered (needs to be disconnected manually, if needed )
- have similar function like internal, but some information are not avabile

### Whitebox external actors:

- defined in [example_whitebox_table.csv](../../../wpa3_test/attack_config/example_whitebox_table.csv)

  [ExternalConn.cpp](../../../wpa3_test/src/ex_program/external_actors/ExternalConn.cpp) \
  |-  [OpenWrtConn.cpp](../../../wpa3_test/src/ex_program/external_actors/openwrt/OpenWrtConn.cpp)

### Blackbox external actors

- scan implicitly with external list from `channel:`, can be overwritten with root `scan_channels:`
- in config can be `scan_until_match`  - test scan with wait until conditions are matched
- connection can be set as requirements

```
  requirements:
        ex_BB_connection : [[ap, client]]
```