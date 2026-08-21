#pragma once
#include <tins/tins.h>

namespace wpa3_tester{
class McMitm;
class McMitmHooks{
public:
	virtual ~McMitmHooks() = default;

	// before probe response on rogue channel
	// attack can change it
	virtual void on_probe_response(Tins::Dot11ProbeResponse &) {}

	// run before default beacon
	// return true if function should NOT continue to default
	virtual bool send_periodic_beacon(McMitm &) { return false; }

	// before AssocRequest rx on rogue channel
	// return true if function should NOT continue to default
	virtual bool on_assoc_request(McMitm &, Tins::Dot11 &, Tins::HWAddress<6> /*addr2*/) { return false; }

	virtual void on_client_connected(McMitm &) {}
};

}