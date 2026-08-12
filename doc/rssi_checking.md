### RSSI 
- its intensity -> dBm, lower = stronger
- some test results depends on how strong is signal - it is checked by receiver
- some client during scanning check RSSI and decide for strongest 
  (some clients ignore more secure APs if stronger exists) #TODO source

### Issues:
- USB issues ()
- Wi-Fi adapters next to each other can make noise 
  
#### RSSI wizard
- [rssi_wizard](../wpa3_test/src/wizard/rssi_wizard.cpp)
- Keys: P -> pause visual gnuplot update, Ctrl+C -> exit window
- check logical conditions for stop ([rssi_condition.cpp](../wpa3_test/src/wizard/rssi_condition.cpp))
- lenght/value A<->B
  - both direction -> (A->B + B->A)/2
  - only one -> (A->B)
  - none -> visually 90dBm, every condition with it is invalid 