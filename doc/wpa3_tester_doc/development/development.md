### Code culture
- [attacks](wpa3_test/src/attacks), [attack_config](wpa3_test/attack_config) and [tests](tests) have same folder structure

#### How to add new attack?

- strictly recommended add wrapper first when PoC is available
- add code to [src](wpa3_test/src), header to  [include](wpa3_test/include)
- add [attack_config](wpa3_test/attack_config) (add schema.yaml if you want) //TODO link to config desctiotion
- add  attack functions to [attacks.h](wpa3_test/include/attacks/attacks.h)
