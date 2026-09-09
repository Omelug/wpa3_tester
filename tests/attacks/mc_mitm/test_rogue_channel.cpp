#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <tins/tins.h>
#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/wifi_util.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "mitm_helpers.h"
#include "pcap_helper.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

namespace wpa3_tester{

namespace {
// create fixture with AP/client MACs taken directly from a pcap frame (for EAPOL tests)
// rogue channel: addr1=AP(dst), addr2=STA(src)
unique_ptr<McMitmTestable> make_rogue_eapol_fixture(const char *pcap_path,
                                                     HWAddress<6> &out_a1, HWAddress<6> &out_a2) {
    auto [rt, raw] = test_helpers::load_frame(pcap_path);
    const auto addrs = get_addrs(rt, raw);
    out_a1 = addrs.addr1;
    out_a2 = addrs.addr2;

    auto r_sta = ActorPtr(make_shared<Actor_Config_internal>());
    auto r_ap  = ActorPtr(make_shared<Actor_Config_internal>());
    auto sta   = ActorPtr(make_shared<Actor_Config_internal>());
    auto ap    = ActorPtr(make_shared<Actor_Config_internal>());
    r_sta->set(SK::iface, "wlan1");
    r_ap->set(SK::iface, "wlan2");
    sta->set(SK::mac, addrs.addr2.to_string()); // STA = src
    ap->set(SK::mac,  addrs.addr1.to_string()); // AP  = dst
    ap->set(SK::ssid, string("test"));
    return make_unique<McMitmTestable>(r_sta, r_ap, sta, ap);
}
} // namespace

// -----------------
TEST_SUITE("handle_probe") {

    TEST_CASE("ProbeRequest broadcast (wildcard) -> STOP, 1 rogue send, state=Finding") {
        auto m = make_fixture();
        m->probe_resp = make_unique<Dot11ProbeResponse>();
        m->probe_resp->addr2(HWAddress<6>(AP_MAC));
        m->probe_resp->addr3(HWAddress<6>(AP_MAC));
        m->client_state.update_state(ClientState::Sent_to_rogue);

        Dot11ProbeRequest req;
        req.addr1(HWAddress<6>::broadcast);
        req.addr2(HWAddress<6>(CLIENT_MAC));

        CHECK_EQ(m->handle_probe(HWAddress<6>(CLIENT_MAC), &req, req), STOP);
        CHECK_EQ(m->rogue_send_count, 1);
        CHECK(m->client_state.is_state(ClientState::Finding));
    }

    TEST_CASE("ProbeRequest addr1 = other AP MAC -> STOP, no send (filtered)") {
        auto m = make_fixture();
        m->probe_resp = make_unique<Dot11ProbeResponse>();
        m->probe_resp->addr2(HWAddress<6>(AP_MAC));

        Dot11ProbeRequest req;
        req.addr1(HWAddress<6>("de:ad:be:ef:00:01")); // different AP, not us, not broadcast
        req.addr2(HWAddress<6>(CLIENT_MAC));

        CHECK_EQ(m->handle_probe(HWAddress<6>(CLIENT_MAC), &req, req), STOP);
        CHECK_EQ(m->rogue_send_count, 0);
    }

    TEST_CASE("ProbeRequest addr1 == AP_MAC -> STOP, 1 rogue send, state=Finding") {
        auto m = make_fixture();
        m->probe_resp = make_unique<Dot11ProbeResponse>();
        m->probe_resp->addr2(HWAddress<6>(AP_MAC));
        m->probe_resp->addr3(HWAddress<6>(AP_MAC));
        m->client_state.update_state(ClientState::Sent_to_rogue);

        Dot11ProbeRequest req;
        req.addr1(HWAddress<6>(AP_MAC));
        req.addr2(HWAddress<6>(CLIENT_MAC));
        req.ssid("test_mc_mitm");

        CHECK_EQ(m->handle_probe(HWAddress<6>(CLIENT_MAC), &req, req), STOP);
        CHECK_EQ(m->rogue_send_count, 1);
        CHECK(m->client_state.is_state(ClientState::Finding));
    }

    TEST_CASE("ProbeResponse -> STOP, no send") {
        auto m = make_fixture();
        // auto avoids most-vexing-parse (both args are named constants)
        auto resp = Dot11ProbeResponse(HWAddress<6>(CLIENT_MAC), HWAddress<6>(AP_MAC));

        CHECK_EQ(m->handle_probe(HWAddress<6>(AP_MAC), &resp, resp), STOP);
        CHECK_EQ(m->rogue_send_count, 0);
    }

    TEST_CASE("Beacon -> CONTINUE") {
        auto m = make_fixture();
        Dot11Beacon beacon(HWAddress<6>("ff:ff:ff:ff:ff:ff"), HWAddress<6>(AP_MAC));

        CHECK_EQ(m->handle_probe(HWAddress<6>(AP_MAC), &beacon, beacon), CONTINUE);
    }
}

// -----------------
TEST_SUITE("handle_open_auth") {

    TEST_CASE("Auth seq=1 algo=0 -> STOP, rogue+real send, state=Authenticated") {
        auto m = make_fixture();
        m->client_state.update_state(ClientState::Sent_to_rogue);

        auto auth = Dot11Authentication(HWAddress<6>(AP_MAC), HWAddress<6>(CLIENT_MAC));
        auth.auth_algorithm(0);
        auth.auth_seq_number(1);

        CHECK_EQ(m->handle_open_auth(HWAddress<6>(CLIENT_MAC), auth), STOP);
        CHECK_EQ(m->rogue_send_count, 1); // seq=2 reply to rogue
        CHECK_EQ(m->real_send_count,  1); // original forwarded to real
        CHECK(m->client_state.is_state(ClientState::Authenticated));
    }

    TEST_CASE("Auth seq=2 -> CONTINUE, no send") {
        auto m = make_fixture();
        auto auth = Dot11Authentication(HWAddress<6>(AP_MAC), HWAddress<6>(CLIENT_MAC));
        auth.auth_algorithm(0);
        auth.auth_seq_number(2);

        CHECK_EQ(m->handle_open_auth(HWAddress<6>(CLIENT_MAC), auth), CONTINUE);
        CHECK_EQ(m->rogue_send_count, 0);
        CHECK_EQ(m->real_send_count,  0);
    }

    TEST_CASE("Auth algo=1 (SAE) seq=1 -> CONTINUE, no send") {
        auto m = make_fixture();
        auto auth = Dot11Authentication(HWAddress<6>(AP_MAC), HWAddress<6>(CLIENT_MAC));
        auth.auth_algorithm(1); // SAE, not Open System
        auth.auth_seq_number(1);

        CHECK_EQ(m->handle_open_auth(HWAddress<6>(CLIENT_MAC), auth), CONTINUE);
        CHECK_EQ(m->rogue_send_count, 0);
    }

    TEST_CASE("Non-auth frame -> CONTINUE") {
        auto m = make_fixture();
        Dot11Beacon beacon;

        CHECK_EQ(m->handle_open_auth(HWAddress<6>(CLIENT_MAC), beacon), CONTINUE);
    }
}

TEST_SUITE("handle_assoc_request") {

    TEST_CASE("AssocRequest -> CONTINUE (by design), 1 rogue send, state=Associated") {
        auto m = make_fixture();
        m->client_state.update_state(ClientState::Authenticated);

        auto req = Dot11AssocRequest(HWAddress<6>(AP_MAC), HWAddress<6>(CLIENT_MAC));
        req.ssid("test_mc_mitm");

        // ponytail: returns CONTINUE intentionally (see FIXME in source)
        CHECK_EQ(m->handle_assoc_request(HWAddress<6>(CLIENT_MAC), req), CONTINUE);
        CHECK_EQ(m->rogue_send_count, 1);
        CHECK(m->client_state.is_state(ClientState::Associated));
    }

    TEST_CASE("ReAssocRequest -> CONTINUE (by design), 1 rogue send, state=Associated") {
        auto m = make_fixture();
        m->client_state.update_state(ClientState::Authenticated);

        auto req = Dot11ReAssocRequest(HWAddress<6>(AP_MAC), HWAddress<6>(CLIENT_MAC));
        req.addr3(HWAddress<6>(AP_MAC));
        req.current_ap(HWAddress<6>(AP_MAC));

        CHECK_EQ(m->handle_assoc_request(HWAddress<6>(CLIENT_MAC), req), CONTINUE);
        CHECK_EQ(m->rogue_send_count, 1);
        CHECK(m->client_state.is_state(ClientState::Associated));
    }

    TEST_CASE("Beacon -> CONTINUE, no send") {
        auto m = make_fixture();
        Dot11Beacon beacon;

        CHECK_EQ(m->handle_assoc_request(HWAddress<6>(CLIENT_MAC), beacon), CONTINUE);
        CHECK_EQ(m->rogue_send_count, 0);
    }
}

TEST_SUITE("handle_eapol_rogue") {

    TEST_CASE("addr1 != AP_MAC -> CONTINUE") {
        auto m = make_fixture();
        Dot11Beacon beacon;

        CHECK_EQ(m->handle_eapol_rogue(HWAddress<6>("00:00:00:00:00:01"), HWAddress<6>(CLIENT_MAC), beacon), CONTINUE);
        CHECK_EQ(m->real_send_count, 0);
    }

    TEST_CASE("addr2 != client MAC -> CONTINUE") {
        auto m = make_fixture();
        Dot11Beacon beacon;

        CHECK_EQ(m->handle_eapol_rogue(HWAddress<6>(AP_MAC), HWAddress<6>("00:00:00:00:00:02"), beacon), CONTINUE);
        CHECK_EQ(m->real_send_count, 0);
    }

    TEST_CASE("correct addrs, non-EAPOL -> CONTINUE") {
        auto m = make_fixture();
        Dot11Beacon beacon;

        CHECK_EQ(m->handle_eapol_rogue(HWAddress<6>(AP_MAC), HWAddress<6>(CLIENT_MAC), beacon), CONTINUE);
    }

    TEST_CASE("EAPOL M2 from pcap, correct addrs -> STOP, 1 real send") {
        HWAddress<6> addr1, addr2;
        auto m = make_rogue_eapol_fixture("test_data/wifi_util/eapol_m2.pcapng", addr1, addr2);
        REQUIRE_NE(addr2, HWAddress<6>());

        auto [rt, raw] = test_helpers::load_frame("test_data/wifi_util/eapol_m2.pcapng");
        REQUIRE(is_eapol(rt));

        CHECK_EQ(m->handle_eapol_rogue(addr1, addr2, rt), STOP);
        CHECK_EQ(m->real_send_count, 1); // M2 forwarded to real
    }

    TEST_CASE("EAPOL M4 from pcap, state=Associated -> STOP, GotMitm") {
        HWAddress<6> addr1, addr2;
        auto m = make_rogue_eapol_fixture("test_data/wifi_util/eapol_m4.pcapng", addr1, addr2);
        m->client_state.update_state(ClientState::Associated);
        REQUIRE_NE(addr2, HWAddress<6>());

        auto [rt, raw] = test_helpers::load_frame("test_data/wifi_util/eapol_m4.pcapng");
        REQUIRE(is_eapol(rt));

        CHECK_EQ(m->handle_eapol_rogue(addr1, addr2, rt), STOP);
        CHECK_EQ(m->real_send_count, 1); // M4 forwarded
        CHECK(m->client_state.is_state(ClientState::GotMitm));
    }
}

TEST_SUITE("handle_action_rogue") {

    TEST_CASE("non-management frame (data) -> CONTINUE") {
        auto m = make_fixture();
        // auto avoids most-vexing-parse
        auto data = Dot11Data(HWAddress<6>(AP_MAC), HWAddress<6>(CLIENT_MAC));

        CHECK_EQ(m->handle_action_rogue(HWAddress<6>(CLIENT_MAC), data, data), CONTINUE);
    }

    TEST_CASE("management subtype != 13 (beacon=8) -> CONTINUE") {
        auto m = make_fixture();
        auto [rt, raw] = test_helpers::load_frame("test_data/wifi_util/beacon.pcapng");
        auto *dot11 = rt.find_pdu<Dot11>();
        REQUIRE_NE(dot11, nullptr);
        REQUIRE_NE(dot11->subtype(), 13);

        CHECK_EQ(m->handle_action_rogue(HWAddress<6>(CLIENT_MAC), rt, *dot11), CONTINUE);
        CHECK_EQ(m->real_send_count, 0);
    }

    TEST_CASE("Action (subtype=13) from client -> STOP, 1 real send") {
        auto m = make_fixture();
		//TODO check if issud with Action frames, delete if not ?
        // Dot11ManagementFrame has non-public default ctor; use ProbeRequest and override subtype
        Dot11ProbeRequest action;
        action.subtype(13); // override to Action subtype, type stays MANAGEMENT
        action.addr1(HWAddress<6>(AP_MAC));
        action.addr2(HWAddress<6>(CLIENT_MAC));
        action.addr3(HWAddress<6>(AP_MAC));

        CHECK_EQ(m->handle_action_rogue(HWAddress<6>(CLIENT_MAC), action, action), STOP);
        CHECK_EQ(m->real_send_count, 1);
    }
}

}
