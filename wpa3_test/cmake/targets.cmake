target_link_libraries(wpa3_config     PUBLIC wpa3_logger wpa3_ex_program wpa3_observer)
target_link_libraries(wpa3_observer   PUBLIC wpa3_config)
target_link_libraries(wpa3_scan       PUBLIC wpa3_config)
target_link_libraries(wpa3_ex_program PUBLIC wpa3_config)
target_link_libraries(wpa3_setup      PUBLIC wpa3_config wpa3_ex_program wpa3_scan)
target_link_libraries(wpa3_suite      PUBLIC wpa3_config wpa3_logger)
target_link_libraries(wpa3_system     PUBLIC wpa3_config)

target_link_libraries(wpa3_core INTERFACE
        -Wl,--start-group
        wpa3_config
        wpa3_ex_program
        wpa3_observer
        wpa3_setup
        wpa3_scan
        wpa3_suite
        wpa3_system

        # attacks
        wpa3_by_target
        wpa3_components
        wpa3_dos_hard
        wpa3_dos_soft
        wpa3_enterprise
        wpa3_mc_mitm
        wpa3_logger
        -Wl,--end-group
)