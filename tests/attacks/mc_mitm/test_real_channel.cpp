#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "mitm_helpers.h"
#include "pcap_helper.h"
#include <doctest.h>
#include <tins/tins.h>

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

namespace wpa3_tester{

namespace {

// real channel EAPOL: addr1=STA(dst), addr2=AP(src) — fixture sta=addr1, ap=addr2
unique_ptr<McMitmTestable> make_real_eapol_fixture(const char *pcap_path,
                                                    HWAddress<6> &out_a1, HWAddress<6> &out_a2) {
    auto [rt, raw] = test_helpers::load_frame(pcap_path);
    const auto addrs = get_addrs(rt, raw);
    out_a1 = addrs.addr1; // STA (destination)
    out_a2 = addrs.addr2; // AP  (source)

    auto rsta = ActorPtr(make_shared<Actor_Config_internal>());
    auto rap  = ActorPtr(make_shared<Actor_Config_internal>());
    auto sta  = ActorPtr(make_shared<Actor_Config_internal>());
    auto ap   = ActorPtr(make_shared<Actor_Config_internal>());
    rsta->set(SK::iface, "wlan1");
    rap->set(SK::iface, "wlan2");
    sta->set(SK::mac, addrs.addr1.to_string()); // STA = dst
    ap->set(SK::mac,  addrs.addr2.to_string()); // AP  = src
    ap->set(SK::ssid, string("test"));
    return make_unique<McMitmTestable>(rsta, rap, sta, ap);
}
}
/*
TEST_SUITE("handle_probe_real") {

    TEST_CASE("ProbeRequest -> STOP, 1 real send") {
        auto m = make_fixture();
        m->probe_resp = make_unique<Dot11ProbeResponse>();
        m->probe_resp->addr2(HWAddress<6>(AP_MAC));
        m->probe_resp->addr3(HWAddress<6>(AP_MAC));

        Dot11ProbeRequest req;
        req.addr1(HWAddress<6>(AP_MAC));
        req.addr2(HWAddress<6>(CLIENT_MAC));

        CHECK_EQ(m->handle_probe_real(HWAddress<6>(CLIENT_MAC), req), STOP);
        CHECK_EQ(m->real_send_count, 1);
    }

    TEST_CASE("ProbeResponse -> STOP, no send") {
        auto m = make_fixture();
        // auto avoids most-vexing-parse (both args are named constants)
        auto resp = Dot11ProbeResponse(HWAddress<6>(CLIENT_MAC), HWAddress<6>(AP_MAC));

        CHECK_EQ(m->handle_probe_real(HWAddress<6>(AP_MAC), resp), STOP);
        CHECK_EQ(m->real_send_count, 0);
    }

    TEST_CASE("Beacon -> CONTINUE") {
        auto m = make_fixture();
        Dot11Beacon beacon(HWAddress<6>("ff:ff:ff:ff:ff:ff"), HWAddress<6>(AP_MAC));

        CHECK_EQ(m->handle_probe_real(HWAddress<6>(AP_MAC), beacon), CONTINUE);
    }
}*/

TEST_SUITE("handle_auth_from_client_real") {

	TEST_CASE("addr1 == AP_MAC, Auth from unknown MAC -> CONTINUE") {
		auto m = make_fixture();
		m->beacon = make_unique<Dot11Beacon>();

		Dot11Authentication auth(HWAddress<6>(AP_MAC), HWAddress<6>("de:ad:be:ef:00:01"));
		auth.auth_algorithm(0);
		auth.auth_seq_number(1);

		CHECK_EQ(m->handle_auth_from_client_real(HWAddress<6>(AP_MAC), auth), CONTINUE);
		CHECK_EQ(m->real_send_count, 0);
	}

    TEST_CASE("addr1 != AP_MAC -> CONTINUE, no send") {
        auto m = make_fixture();
        auto auth = Dot11Authentication(HWAddress<6>(AP_MAC), HWAddress<6>(CLIENT_MAC));
        auth.auth_algorithm(0);
        auth.auth_seq_number(1);

        CHECK_EQ(m->handle_auth_from_client_real(HWAddress<6>("00:00:00:00:00:01"), auth), CONTINUE);
        CHECK_EQ(m->real_send_count, 0);
    }

    TEST_CASE("addr1 == AP_MAC, Auth from our client -> STOP, CSA beacons sent, state=Sent_to_rogue") {
        auto m = make_fixture();
        m->beacon = make_unique<Dot11Beacon>();
        m->beacon->ssid("test");

        // auth->addr2() must equal client_state.get_mac() == CLIENT_MAC
        auto auth = Dot11Authentication(HWAddress<6>(AP_MAC), HWAddress<6>(CLIENT_MAC));
        auth.auth_algorithm(0);
        auth.auth_seq_number(1);

        CHECK_EQ(m->handle_auth_from_client_real(HWAddress<6>(AP_MAC), auth), STOP);
        CHECK_GT(m->real_send_count, 0); // at least one CSA beacon injected
        CHECK(m->client_state.is_state(ClientState::Sent_to_rogue));
    }
}

TEST_SUITE("handle_eapol_real") {

    TEST_CASE("addr1 != STA MAC -> CONTINUE") {
        auto m = make_fixture();
        Dot11Beacon beacon;

        CHECK_EQ(m->handle_eapol_real(HWAddress<6>("00:00:00:00:00:01"), HWAddress<6>(AP_MAC), beacon), CONTINUE);
        CHECK_EQ(m->rogue_send_count, 0);
    }

    TEST_CASE("addr2 != AP MAC -> CONTINUE") {
        auto m = make_fixture();
        Dot11Beacon beacon;

        CHECK_EQ(m->handle_eapol_real(HWAddress<6>(CLIENT_MAC), HWAddress<6>("00:00:00:00:00:02"), beacon), CONTINUE);
        CHECK_EQ(m->rogue_send_count, 0);
    }

    TEST_CASE("EAPOL M1 from pcap, correct addrs -> STOP, 1 rogue send") {
        HWAddress<6> addr1, addr2;
        auto m = make_real_eapol_fixture("test_data/wifi_util/eapol_m1.pcapng", addr1, addr2);
        REQUIRE_NE(addr2, HWAddress<6>());

        auto [rt, raw] = test_helpers::load_frame("test_data/wifi_util/eapol_m1.pcapng");
        REQUIRE(is_eapol(rt));

        CHECK_EQ(m->handle_eapol_real(addr1, addr2, rt), STOP);
        CHECK_EQ(m->rogue_send_count, 1); // M1 forwarded to rogue
    }
}

TEST_SUITE("handle_from_ap_real") {

    TEST_CASE("Beacon -> no forward, no state change") {
        auto m = make_fixture();
        Dot11Beacon beacon(HWAddress<6>("ff:ff:ff:ff:ff:ff"), HWAddress<6>(AP_MAC));

        unique_ptr<PDU> pdu = make_unique<Dot11Beacon>(beacon);
        auto *dot11 = pdu->find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);

        m->handle_from_ap_real(pdu, *dot11, HWAddress<6>(AP_MAC));

        CHECK_EQ(m->rogue_send_count, 0);
        CHECK(m->client_state.is_state(ClientState::GotMitm)); // unchanged
    }

    TEST_CASE("Deauth to client -> forwarded to rogue, state=Target") {
        auto m = make_fixture();

        auto deauth = Dot11Deauthentication(HWAddress<6>(CLIENT_MAC), HWAddress<6>(AP_MAC));
        deauth.addr3(HWAddress<6>(AP_MAC));
        deauth.reason_code(3);

        unique_ptr<PDU> pdu = make_unique<Dot11Deauthentication>(deauth);
        auto *dot11 = pdu->find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);

        m->handle_from_ap_real(pdu, *dot11, HWAddress<6>(CLIENT_MAC));

        CHECK_EQ(m->rogue_send_count, 1);
        CHECK(m->client_state.is_state(ClientState::Target_disconnected));
    }

    TEST_CASE("Auth seq=2 to client -> dropped (not forwarded)") {
        auto m = make_fixture();

        auto auth = Dot11Authentication(HWAddress<6>(CLIENT_MAC), HWAddress<6>(AP_MAC));
        auth.auth_algorithm(0);
        auth.auth_seq_number(2);
        auth.addr3(HWAddress<6>(AP_MAC));

        unique_ptr<PDU> pdu = make_unique<Dot11Authentication>(auth);
        auto *dot11 = pdu->find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);

        m->handle_from_ap_real(pdu, *dot11, HWAddress<6>(CLIENT_MAC));

        CHECK_EQ(m->rogue_send_count, 0);
    }

    TEST_CASE("Data frame to client -> forwarded to rogue") {
        auto m = make_fixture();

        auto data = Dot11Data(HWAddress<6>(CLIENT_MAC), HWAddress<6>(AP_MAC));
        data.addr3(HWAddress<6>(AP_MAC));

        unique_ptr<PDU> pdu = make_unique<Dot11Data>(data);
        auto *dot11 = pdu->find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);

        m->handle_from_ap_real(pdu, *dot11, HWAddress<6>(CLIENT_MAC));

        CHECK_EQ(m->rogue_send_count, 1);
    }
}

}
