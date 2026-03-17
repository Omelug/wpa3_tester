#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include "config/RunStatus.h"
#include "system/hw_capabilities.h"
#include <memory>
#include <tins/tins.h>

using namespace std;
using namespace wpa3_tester;
using namespace Tins;
namespace wpa3_tester {

    TEST_CASE("RunStatus::solve_new_pdu - Beacon frame") {
        ActorMap seen;
        
        auto beacon = make_shared<Dot11Beacon>();
        beacon->addr2("00:11:22:33:44:55");  // AP MAC
        beacon->ssid("TestNetwork");
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(2437, 6);  // Channel 6, ERP type (802.11g)
        radiotap->dbm_signal(-45);
        radiotap->inner_pdu(*beacon);

        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK((seen.size() == 1));
        CHECK(seen.contains("00:11:22:33:44:55"));
        
        auto actor = seen.at("00:11:22:33:44:55");
        CHECK((actor->str_con["mac"] == "00:11:22:33:44:55"));
        CHECK((actor->str_con["source"] == "external"));
        CHECK((actor->str_con["ssid"] == "TestNetwork"));
        CHECK((actor->str_con["channel"] == "6"));
        CHECK((actor->str_con["signal"] == "-45"));
        CHECK((actor->bool_conditions["AP"] == true));
        CHECK((actor->bool_conditions["2_4GHz"] == true));
    }

    TEST_CASE("RunStatus::solve_new_pdu - Probe Response") {
        ActorMap seen;
        
        auto probe_resp = make_shared<Dot11ProbeResponse>();
        probe_resp->addr2("AA:BB:CC:DD:EE:FF");  // AP MAC
        probe_resp->ssid("HiddenNetwork");
        
        // Create RadioTap with 5 GHz channel
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(5500, 5);  // Channel 100, OFDM type (802.11a)
        radiotap->dbm_signal(-60);
        
        radiotap->inner_pdu(*probe_resp);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK((seen.size() == 1));
        CHECK(seen.contains("AA:BB:CC:DD:EE:FF"));
        
        auto actor = seen.at("AA:BB:CC:DD:EE:FF");
        CHECK((actor->str_con["mac"] == "AA:BB:CC:DD:EE:FF"));
        CHECK((actor->str_con["ssid"] == "HiddenNetwork"));
        CHECK((actor->str_con["channel"] == "100"));
        CHECK((actor->str_con["signal"] == "-60"));
        CHECK((actor->bool_conditions["AP"] == true));
        CHECK((actor->bool_conditions["5GHz"] == true));
    }

    TEST_CASE("RunStatus::solve_new_pdu - Probe Request") {
        ActorMap seen;
        
        auto probe_req = make_shared<Dot11ProbeRequest>();
        probe_req->addr2("11:22:33:44:55:66");  // STA MAC
        probe_req->ssid("MyNetwork");
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(2412, 6);  // Channel 1, ERP type (802.11g)
        radiotap->dbm_signal(-70);
        
        radiotap->inner_pdu(*probe_req);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK((seen.size() == 1));
        CHECK((seen.contains("11:22:33:44:55:66")));
        
        auto actor = seen.at("11:22:33:44:55:66");
        CHECK((actor->str_con["mac"] == "11:22:33:44:55:66"));
        CHECK((actor->str_con["ssid"] == "MyNetwork"));
        CHECK((actor->bool_conditions["AP"] == false));
        CHECK((actor->bool_conditions["2_4GHz"] == true));
    }

    TEST_CASE("RunStatus::solve_new_pdu - Data frame STA->AP") {
        ActorMap seen;
        
        // Create data frame from STA to AP
        auto data = make_shared<Dot11Data>();
        data->addr2("22:33:44:55:66:77");  // STA MAC (source)
        data->addr1("AA:BB:CC:DD:EE:FF");  // AP MAC (destination)
        data->to_ds(true);
        data->from_ds(false);
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(5180, 7);  // Channel 36, HT type (802.11n)
        radiotap->dbm_signal(-55);
        
        radiotap->inner_pdu(*data);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK((seen.size() == 2));
        CHECK((seen.contains("22:33:44:55:66:77")));  // STA
        CHECK((seen.contains("AA:BB:CC:DD:EE:FF")));   // AP
        
        // Check STA
        auto sta = seen.at("22:33:44:55:66:77");
        CHECK((sta->bool_conditions["AP"] == false));
        CHECK((sta->str_con["channel"] == "36"));
        
        // Check AP
        auto ap = seen.at("AA:BB:CC:DD:EE:FF");
        CHECK((ap->bool_conditions["AP"] == true));
        CHECK((ap->str_con["channel"] == "36"));
    }

    TEST_CASE("RunStatus::solve_new_pdu - Data frame AP->STA") {
        ActorMap seen;
        
        // Create data frame from AP to STA
        auto data = make_shared<Dot11Data>();
        data->addr2("AA:BB:CC:DD:EE:FF");  // AP MAC (source)
        data->addr1("22:33:44:55:66:77");  // STA MAC (destination)
        data->to_ds(false);
        data->from_ds(true);
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(5885, 8);  // Channel 177, VHT type (802.11ac)
        radiotap->dbm_signal(-40);
        
        radiotap->inner_pdu(*data);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK((seen.size() == 2));
        CHECK(seen.contains("AA:BB:CC:DD:EE:FF"));   // AP
        CHECK(seen.contains("22:33:44:55:66:77"));  // STA
        
        auto ap = seen.at("AA:BB:CC:DD:EE:FF");
        CHECK((ap->bool_conditions["AP"] == true));
        CHECK((ap->str_con["channel"] == "177"));
        CHECK((ap->bool_conditions["5GHz"] == true));
    }

    TEST_CASE("RunStatus::solve_new_pdu - Update existing entity") {
        ActorMap seen;
        
        // First add an entity with basic info
        auto actor = make_shared<Actor_config>();
        actor->str_con["mac"] = "00:11:22:33:44:55";
        actor->str_con["source"] = "external";
        seen.emplace("00:11:22:33:44:55", ActorPtr(actor));
        
        // Create beacon with more info
        auto beacon = make_shared<Dot11Beacon>();
        beacon->addr2("00:11:22:33:44:55");
        beacon->ssid("UpdatedSSID");
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(2472, 6);  // Channel 13, ERP type (802.11g)
        radiotap->dbm_signal(-50);
        
        radiotap->inner_pdu(*beacon);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK((seen.size() == 1));
        auto updated_actor = seen.at("00:11:22:33:44:55");
        CHECK((updated_actor->str_con["ssid"] == "UpdatedSSID"));
        CHECK((updated_actor->str_con["channel"] == "13"));
        CHECK((updated_actor->str_con["signal"] == "-50"));
    }

    TEST_CASE("RunStatus::solve_new_pdu - No RadioTap") {
        ActorMap seen;
        
        // Create beacon without RadioTap
        auto beacon = make_shared<Dot11Beacon>();
        beacon->addr2("00:11:22:33:44:55");
        beacon->ssid("NoRadioTap");
        
        RunStatus::solve_new_pdu(*beacon, seen);
        
        CHECK((seen.size() == 1));
        auto actor = seen.at("00:11:22:33:44:55");
        CHECK((actor->str_con["ssid"] == "NoRadioTap"));
        CHECK((actor->str_con["channel"] == "-1"));  // Default value
        CHECK((actor->str_con["signal"] == "-1"));   // Default value
    }

    TEST_CASE("RunStatus::solve_new_pdu - 6 GHz band") {
        ActorMap seen;
        
        // Create beacon on 6 GHz
        auto beacon = make_shared<Dot11Beacon>();
        beacon->addr2("66:77:88:99:AA:BB");
        beacon->ssid("SixGHzNetwork");
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(6455, 8);  // Channel 101, VHT type (802.11ac)
        radiotap->dbm_signal(-65);
        
        radiotap->inner_pdu(*beacon);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK((seen.size() == 1));
        auto actor = seen.at("66:77:88:99:AA:BB");
        CHECK((actor->str_con["channel"] == "101"));
        CHECK((actor->bool_conditions["6GHz"] == true));
    }

    TEST_CASE("RunStatus::solve_new_pdu - WDS/IBSS frames ignored") {
        ActorMap seen;
        
        // Create WDS frame (to_ds && from_ds)
        auto data = make_shared<Dot11Data>();
        data->addr2("00:11:22:33:44:55");
        data->addr1("66:77:88:99:AA:BB");
        data->to_ds(true);
        data->from_ds(true);  // WDS
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(2437, 6);
        
        radiotap->inner_pdu(*data);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        // Should be ignored, no entities added
        CHECK((seen.size() == 0));
    }
}
