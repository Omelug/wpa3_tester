#include <tins/tins.h>
#include "attacks/mc_mitm/mc_mitm.h"
#include "config/Actor_Config/Actor_Config_internal.h"
#include "config/Actor_Config/Actor_Config_sim.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

int main(){
    const auto r_sta_actor = ActorPtr(std::make_shared<Actor_Config_sim>());
    const auto r_ap_actor = ActorPtr(std::make_shared<Actor_Config_sim>());

    r_sta_actor->set(SK::iface, "wlan1");
    r_sta_actor->set(SK::iface, "wlan2");

    const string ap_ssid = "test_mc_mitm";
    const string ap_mac = "02:00:00:00:03:00";
    //const string client_mac     = "30:ab:6a:39:88:46";
    const string client_mac = "02:00:00:00:02:00";
    constexpr Channel real_channel{11, WifiBand::BAND_2_4, nullopt};
    constexpr Channel rogue_channel{1, WifiBand::BAND_2_4, nullopt};
    constexpr int attack_time = 20;

    McMitm attack(r_sta_actor, r_ap_actor, ap_ssid, ap_mac, client_mac);

    attack.netconfig.real_channel = real_channel;
    attack.netconfig.rogue_channel = rogue_channel;
    attack.netconfig.ssid = ap_ssid;

    RunStatus rs;
    attack.run(rs, attack_time);

    return 0;
}