#pragma once
#include "mc_mitm_hooks.h"
#include <tins/tins.h>

namespace wpa3_tester {
class McMitm;
class SsidConfusionHooks : public McMitmHooks{
public:
	SsidConfusionHooks(std::string real_ssid, std::string confused_ssid, bool strip_rsn)
		: real_ssid_(std::move(real_ssid)),
		  confused_ssid_(std::move(confused_ssid)),
		  strip_rsn_(strip_rsn) {}

	void on_probe_response(Tins::Dot11ProbeResponse &resp) override;
	bool send_periodic_beacon(McMitm &m) override;
	bool on_assoc_request(McMitm &m, Tins::Dot11 &dot11,
						  Tins::HWAddress<6> addr2) override;

private:
	std::string real_ssid_{}, confused_ssid_{};
	bool strip_rsn_;
};
}