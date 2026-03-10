#pragma once
namespace wpa3_tester{
    class OpenWrtConn{
        // get max RAM, CPU
        void get_hw_info();
        // get hostapd version, openwrt info
        void get_openwrt_info();
    };
}