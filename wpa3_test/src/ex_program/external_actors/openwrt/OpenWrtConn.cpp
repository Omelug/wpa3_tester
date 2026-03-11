#include "ex_program/external_actors/openwrt/OpenWrtConn.h"
#include <stdexcept>

namespace wpa3_tester {
    using namespace std;

    // UCI helpers
    string OpenWrtConn::uci_get(const string& path) const{
        return exec("uci get " + path);
    }

    void OpenWrtConn::uci_set(const string& path, const string& value) const{
        exec("uci set " + path + "='" + value + "'");
        exec("uci commit");
    }
}
