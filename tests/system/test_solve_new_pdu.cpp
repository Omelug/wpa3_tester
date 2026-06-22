#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <memory>
#include <tins/tins.h>

#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace wpa3_tester;
using namespace Tins;

namespace wpa3_tester{
TEST_CASE("RunStatus::solve_new_pdu - Beacon frame"){
        ActorMACMap seen;
        auto beacon = make_shared<Dot11Beacon>();
        beacon->addr2("00:11:22:33:44:55");  // AP MAC
        beacon->ssid("TestNetwork");
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(2437, 6);  // Channel 6, ERP type (802.11g)
        radiotap->dbm_signal(-45);
        radiotap->inner_pdu(*beacon);

        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK_EQ(seen.size(), 1);
        CHECK(seen.contains("00:11:22:33:44:55"));
        
        auto actor = seen.at("00:11:22:33:44:55");
        CHECK_EQ(actor[SK::mac], "00:11:22:33:44:55");
        CHECK_EQ(actor[SK::source], "external");
        CHECK_EQ(actor[SK::ssid], "TestNetwork");
        CHECK_EQ(actor[SK::channel], "6");
        CHECK_EQ(actor[SK::signal], "-45");
        CHECK(actor[BK::AP]);
        CHECK(actor[BK::GHz2_4]);
    }

TEST_CASE("RunStatus::solve_new_pdu - Probe Response"){
        ActorMACMap seen;
        
        auto probe_resp = make_shared<Dot11ProbeResponse>();
        probe_resp->addr2("AA:BB:CC:DD:EE:FF");  // AP MAC
        probe_resp->ssid("HiddenNetwork");

        // Create RadioTap with 5 GHz channel
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(5500, 5);  // Channel 100, OFDM type (802.11a)
        radiotap->dbm_signal(-60);
        
        radiotap->inner_pdu(*probe_resp);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK_EQ(seen.size(), 1);
        CHECK(seen.contains("aa:bb:cc:dd:ee:ff"));
        
        auto actor = seen.at("aa:bb:cc:dd:ee:ff");
        CHECK_EQ(actor[SK::mac], "aa:bb:cc:dd:ee:ff");
        CHECK_EQ(actor[SK::ssid], "HiddenNetwork");
        CHECK_EQ(actor[SK::channel], "100");
        CHECK_EQ(actor[SK::signal], "-60");
        CHECK(actor[BK::AP]);
        CHECK(actor[BK::GHz5]);
    }

TEST_CASE("RunStatus::solve_new_pdu - Probe Request"){
        ActorMACMap seen;
        
        auto probe_req = make_shared<Dot11ProbeRequest>();
        probe_req->addr2("12:22:33:44:55:66");  // STA MAC (unicast: byte0=0x12, bit0=0)
        probe_req->ssid("MyNetwork");

        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(2412, 6);  // Channel 1, ERP type (802.11g)
        radiotap->dbm_signal(-70);

        radiotap->inner_pdu(*probe_req);

        RunStatus::solve_new_pdu(*radiotap, seen);

        CHECK_EQ(seen.size(), 1);
		CHECK(seen.contains("12:22:33:44:55:66"));

        auto actor = seen.at("12:22:33:44:55:66");
        CHECK_EQ(actor[SK::mac], "12:22:33:44:55:66");
        CHECK_EQ(actor[SK::ssid], "MyNetwork");
        CHECK_EQ(actor[BK::AP], false);
        CHECK(actor[BK::GHz2_4]);
    }

TEST_CASE("RunStatus::solve_new_pdu - Data frame STA->AP"){
        ActorMACMap seen;

        // Create data frame from STA to AP
        auto data = make_shared<Dot11Data>();
        data->addr2("22:33:44:55:66:77");  // STA MAC (source)
        data->addr1("AA:BB:CC:DD:EE:FF");  // AP MAC (destination)
        data->to_ds(true);
        data->from_ds(false);
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(5180, 7);  // channel 36, HT type (802.11n)
        radiotap->dbm_signal(-55);
        
        radiotap->inner_pdu(*data);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK_EQ(seen.size(), 2);
        CHECK((seen.contains("22:33:44:55:66:77")));  // STA
        CHECK((seen.contains("aa:bb:cc:dd:ee:ff")));   // AP

        // Check STA
        auto sta = seen.at("22:33:44:55:66:77");
        CHECK_EQ(sta[BK::AP], false);
        CHECK_EQ(sta[SK::channel], "36");

        // Check AP
        auto ap = seen.at("aa:bb:cc:dd:ee:ff");
        CHECK(ap[BK::AP]);
        CHECK_EQ(ap[SK::channel], "36");
    }

TEST_CASE("RunStatus::solve_new_pdu - Data frame AP->STA"){
        ActorMACMap seen;

        // Create data frame from AP to STA
        auto data = make_shared<Dot11Data>();
        data->addr2("aa:bb:cc:dd:ee:ff");  // AP MAC (source)
        data->addr1("22:33:44:55:66:77");  // STA MAC (destination)
        data->to_ds(false);
        data->from_ds(true);
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(5885, 8);  // Channel 177, VHT type (802.11ac)
        radiotap->dbm_signal(-40);
        
        radiotap->inner_pdu(*data);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK_EQ(seen.size(), 2);
        CHECK(seen.contains("aa:bb:cc:dd:ee:ff"));   // AP
        CHECK(seen.contains("22:33:44:55:66:77"));  // STA

        auto ap = seen.at("aa:bb:cc:dd:ee:ff");
        CHECK(ap[BK::AP]);
        CHECK_EQ(ap[SK::channel], "177");
        CHECK(ap[BK::GHz5]);
    }

TEST_CASE("RunStatus::solve_new_pdu - Update existing entity"){
        ActorMACMap seen;

        // First add an entity with basic info
        auto actor = ActorPtr(make_shared<Actor_Config_external>());
        actor->set(SK::mac, "00:11:22:33:44:55");
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
        
        CHECK_EQ(seen.size(), 1);
        auto updated_actor = seen.at("00:11:22:33:44:55");
        CHECK_EQ(updated_actor[SK::ssid], "UpdatedSSID");
        CHECK_EQ(updated_actor[SK::channel], "13");
        CHECK_EQ(updated_actor[SK::signal], "-50");
    }

TEST_CASE("RunStatus::solve_new_pdu - No RadioTap"){
        ActorMACMap seen;

        // Create beacon without RadioTap
        auto beacon = make_shared<Dot11Beacon>();
        beacon->addr2("00:11:22:33:44:55");
        beacon->ssid("NoRadioTap");
        
        RunStatus::solve_new_pdu(*beacon, seen);
        
        CHECK_EQ(seen.size(), 1);
        auto actor = seen.at("00:11:22:33:44:55");
        CHECK_EQ(actor[SK::ssid], "NoRadioTap");
    }

TEST_CASE("RunStatus::solve_new_pdu - 6 GHz band"){
        ActorMACMap seen;

        // Create beacon on 6 GHz
        auto beacon = make_shared<Dot11Beacon>();
        beacon->addr2("66:77:88:99:AA:BB");
        beacon->ssid("SixGHzNetwork");
        
        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(6455, 8);  // Channel 101, VHT type (802.11ac)
        radiotap->dbm_signal(-65);
        
        radiotap->inner_pdu(*beacon);
        
        RunStatus::solve_new_pdu(*radiotap, seen);
        
        CHECK_EQ(seen.size(), 1);
        auto actor = seen.at("66:77:88:99:aa:bb");
        CHECK_EQ(actor[SK::channel], "101");
        CHECK(actor[BK::GHz6]);
    }

TEST_CASE("RunStatus::solve_new_pdu - WDS/IBSS frames ignored"){
        ActorMACMap seen;

        // Create WDS frame (to_ds && from_ds)
        auto data = make_shared<Dot11Data>();
        data->addr2("00:11:22:33:44:55");
        data->addr1("66:77:88:99:aa:bb");
        data->to_ds(true);
        data->from_ds(true);  // WDS

        auto radiotap = make_shared<RadioTap>();
        radiotap->channel(2437, 6);
        
        radiotap->inner_pdu(*data);
        
        RunStatus::solve_new_pdu(*radiotap, seen);

        // Should be ignored, no entities added
        CHECK_EQ(seen.size(), 0);
    }
}