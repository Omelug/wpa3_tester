#include "attacks/DoS_hard/dos_helpers.h"
#include <logger/error_log.h>

#include "ex_program/external_actors/ExternalConn.h"

extern "C"{
#include "radiotap.h"
#include "radiotap_iter.h"
}

#include "logger/log.h"

using namespace std;
using namespace Tins;

namespace wpa3_tester::dos_helpers{

// TODO make alternative external WB
vector<HWAddress<6>> get_connected_stas(RunStatus &rs){
	const ActorPtr ap = rs.get_actor("access_point");
	vector<HWAddress<6>> result;

	const string out = ap->conn->exec(
		"iw dev $(iw dev | awk '/Interface/{print $2}' | head -1) station dump 2>/dev/null");

	istringstream ss(out);
	string line;
	while(getline(ss, line)){
		if(line.rfind("Station", 0) != 0) continue;
		istringstream ls(line);
		string token, mac_str;
		ls >> token >> mac_str; // "Station" "<mac>"
		try{
			result.emplace_back(mac_str);
		} catch(...){}
	}
	log(LogLevel::INFO, " Found {} connected STAs", result.size());
	return result;
}

bool check_fcs_present(const vector<uint8_t> &packet){
	ieee80211_radiotap_iterator it;

	if(ieee80211_radiotap_iterator_init(&it,
		reinterpret_cast<ieee80211_radiotap_header *>(
			const_cast<uint8_t *>(packet.data())),
		static_cast<int>(packet.size()), nullptr) != 0)
		return false;

	while(ieee80211_radiotap_iterator_next(&it) == 0){
		if(it.this_arg_index == IEEE80211_RADIOTAP_FLAGS && it.this_arg != nullptr)
			return (*it.this_arg & 0x10) != 0;
	}

	return false;
}
}