#include "config/Actor_Config/Actor_Config_external.h"
#include "config/Actor_Config/actor_keys.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace filesystem;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::scan{
// ----------- Fill Actor_Config ------------------
void apply_radiotap(PDU &pdu, Actor_Config_external &cfg){
	const auto *rt = pdu.find_pdu<RadioTap>();
	if(!rt) return;
	try{ cfg.set(SK::signal, to_string(rt->dbm_signal())); } catch(...){
		// signal option not found
	}
	try{
		const int freq = rt->channel_freq();
		if(freq > 0){
			cfg.set(SK::channel, to_string(hw_capabilities::freq_to_channel(freq)));
			if(freq >= 2412 && freq <= 2484){
				cfg.set(BK::GHz2_4, true);
				cfg.set(BK::GHz5, false);
				cfg.set(BK::GHz6, false);
			} else if(freq >= 5170 && freq <= 5885){
				cfg.set(BK::GHz2_4, false);
				cfg.set(BK::GHz5, true);
				cfg.set(BK::GHz6, false);
			} else if(freq >= 5945 && freq <= 7125){
				cfg.set(BK::GHz2_4, false);
				cfg.set(BK::GHz5, false);
				cfg.set(BK::GHz6, true);
			}
		}
	} catch(...){
		// channel option not foud
	}
}

void apply_rsn(const Dot11ManagementFrame &mgmt, Actor_Config_external &cfg){
	try{
		const auto rsn = mgmt.rsn_information();
		const uint16_t caps = rsn.capabilities();
		cfg.set(BK::MFP, static_cast<bool>(caps & 1u << 7));
		cfg.set(BK::OCV, static_cast<bool>(caps & 1u << 10));
		cfg.set(BK::beacon_prot, static_cast<bool>(caps & 1u << 11));

		bool wpa2_psk = false, wpa3_sae = false;
		for(const auto &akm: rsn.akm_cyphers()){
			if(akm == RSNInformation::PSK || akm == RSNInformation::PSK_FT || akm ==
				RSNInformation::PSK_SHA256) wpa2_psk = true;
			if(akm == RSNInformation::SAE_SHA256 || akm == RSNInformation::SAE_FT) wpa3_sae = true;
		}
		cfg.set(BK::WPA_PSK, wpa2_psk);
		cfg.set(BK::WPA3_SAE, wpa3_sae);
	} catch(...){}
}

void apply_ht_vht_he(const Dot11ManagementFrame &mgmt, Actor_Config_external &cfg){
	using OT = Dot11ManagementFrame::OptionTypes;

	// HT Capabilities (IE 45) → 802.11n
	const bool has_ht = mgmt.search_option(OT::HT_CAPABILITY) != nullptr;
	cfg.set(BK::w80211n, has_ht);

	if(has_ht){
		// HT Operation (IE 61): byte 1 bits 0-1 = secondary channel offset
		// 0=none(HT20), 1=above(HT40+), 3=below(HT40-)
		const auto *ht_op = mgmt.search_option(OT::HT_OPERATION);
		if(ht_op && ht_op->data_size() >= 2){
			switch(ht_op->data_ptr()[1] & 0x03){
			case 1: cfg.set(SK::ht_mode, "HT40+");
				break;
			case 3: cfg.set(SK::ht_mode, "HT40-");
				break;
			default: cfg.set(SK::ht_mode, "HT20");
				break;
			}
		} else{
			cfg.set(SK::ht_mode, "HT20");
		}
	}

	// VHT Capabilities (IE 191) → 802.11ac
	cfg.set(BK::w80211ac, mgmt.search_option(OT::VHT_CAP) != nullptr);

	// HE Capabilities: extension element (IE 255, ext ID 35) → 802.11ax
	// Iterate all options to find the multi-occurrence extension element.
	bool has_he = false;
	for(const auto &opt: mgmt.options()){
		if(opt.option() == static_cast<OT>(255) && opt.data_size() > 0 && opt.data_ptr()[0] == 35){
			has_he = true;
			break;
		}
	}
	cfg.set(BK::w80211ax, has_he);
}
}
