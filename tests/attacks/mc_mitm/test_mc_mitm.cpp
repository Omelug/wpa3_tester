#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <vector>
#include "attacks/mc_mitm/mc_mitm.h"
#include "pcap_helper.h"

using namespace std;
using namespace Tins;
using namespace wpa3_tester;

TEST_CASE("MonitorSocket receives all auth frames from pcap") {
	const string pcap_path = "./test_data/rogue_client_capture.pcapng";

	const HWAddress<6> ap_mac = "78:98:e8:55:3e:8d";
	const HWAddress<6> client_mac = "24:ec:99:bf:c7:cf";

	int expected_ap_to_client = 0;
	int expected_client_to_ap = 0;

	FileSniffer file_sniffer(pcap_path);
	file_sniffer.sniff_loop([&](PDU &pdu) -> bool {
		const auto *mgmt = pdu.find_pdu<Dot11ManagementFrame>();
		if(!mgmt) return true;
		if(!pdu.find_pdu<Dot11Authentication>()) return true;

		if(mgmt->addr2() == ap_mac && mgmt->addr1() == client_mac)
			expected_ap_to_client++;
		else if(mgmt->addr2() == client_mac && mgmt->addr1() == ap_mac)
			expected_client_to_ap++;
		return true;
	});

	REQUIRE_GT(expected_ap_to_client, 0);
	REQUIRE_GT(expected_client_to_ap, 0);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(pcap_path.c_str(), errbuf);
	REQUIRE_NE(handle, nullptr);

	int got_ap_to_client = 0;
	int got_client_to_ap = 0;

	pcap_pkthdr *header;
	const u_char *frame;
	while(pcap_next_ex(handle, &header, &frame) == 1) {
		try {
			RadioTap rt(frame, header->caplen);
			const auto *mgmt = rt.find_pdu<Dot11ManagementFrame>();
			if(!mgmt) continue;
			if(!rt.find_pdu<Dot11Authentication>()) continue;

			if(mgmt->addr2() == ap_mac && mgmt->addr1() == client_mac)
				got_ap_to_client++;
			else if(mgmt->addr2() == client_mac && mgmt->addr1() == ap_mac)
				got_client_to_ap++;
		} catch(...) {}
	}

	pcap_close(handle);
	CHECK_EQ(got_ap_to_client, expected_ap_to_client);
	CHECK_EQ(got_client_to_ap, expected_client_to_ap);
}