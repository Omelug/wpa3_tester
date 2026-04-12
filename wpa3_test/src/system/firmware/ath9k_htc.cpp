#include <iomanip>
#include <ios>
#include <iosfwd>
#include <random>
#include <string>
#include <vector>
#include <bits/ios_base.h>

#include "config/global_config.h"
#include "system/hw_capabilities.h"

using namespace std;

namespace wpa3_tester::firmware{
    //TODO change funciton to work with Adress object, not string
    string get_ath_masker_mac(const string& attacker_mac) {
        stringstream ss(attacker_mac);
        string segment;
        vector<string> parts;

        while (getline(ss, segment, ':')) { parts.push_back(segment);}

        string result;
        for (int i = 0; i < 5; ++i) { result += parts[i] + ":"; }

        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(1, 255); //TODO in dragondrain test it dont ACK zero
        int random_byte = dis(gen);

        stringstream hex_ss;
        hex_ss << hex << setw(2) << setfill('0') << random_byte;
        result += hex_ss.str();
        return result;
    }

    void load_ath_masker(){
        const string ath_folder = get_global_config().at("paths").at("dragondrain").at("ath_folder");
        hw_capabilities::run_in("bash ./load.sh", ath_folder);
    }
}