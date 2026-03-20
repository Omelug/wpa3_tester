#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include <tins/tins.h>
#include <atomic>
using namespace Tins;
using namespace wpa3_tester::cookie_guzzler;

TEST_CASE("SAECallback ParsesCommitFromPcap") {
    atomic running{true};

    // Use the real pcap file
    filesystem::path pcap_path = filesystem::path(PROJECT_ROOT_DIR) / "../tests/attacks/DoS_hard/cookie_guzzler/test_sae_commit.pcapng";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_path.string().c_str(), errbuf);
    REQUIRE((handle != nullptr));

    pcap_pkthdr *header;
    const uint8_t *packet;
    optional<SAEPair> result;

    while (pcap_next_ex(handle, &header, &packet) > 0) {
        result = parse_sae_commit(packet, header->caplen);
        if (result) break;
    }

    pcap_close(handle);

    REQUIRE(result.has_value());
    CHECK((result->scalar.size()  == 32));
    const vector<uint8_t> expected_scalar = {0xcd, 0x3a, 0x57, 0x89, 0xa1, 0x86, 0xa7, 0xae, 0x9f, 0x2d, 0xcc, 0xb1, 0x6a, 0x70, 0xc9, 0xaf, 0xc7, 0xb4, 0x7c, 0xb0, 0x7e, 0x51, 0x9f, 0x66, 0x1f, 0xb3, 0xe9, 0x5, 0x8d, 0xb2, 0x1a, 0xb4};
    CHECK((result->scalar == expected_scalar));
    CHECK((result->element.size() == 64));
    const vector<uint8_t> expected_element = {0xeb, 0x90, 0x1b, 0xf1, 0xf2, 0xcd, 0x4a, 0x61, 0x75, 0xa5, 0x14, 0xdf, 0xaf, 0x49, 0xf9, 0x13, 0x33, 0x54, 0x43, 0x86, 0xc8, 0x57, 0x8d, 0xce, 0xe7, 0x9f, 0x17, 0x6e, 0xb7, 0x30, 0x43, 0x38, 0xbe, 0xe0, 0x10, 0xc, 0x72, 0x63, 0xb5, 0xf6, 0xa3, 0x67, 0x24, 0xc7, 0x59, 0xa7, 0x29, 0x9f, 0x51, 0x9a, 0xa3, 0x8f, 0xa7, 0x64, 0xc5, 0xae, 0xe4, 0xa2, 0xf4, 0x5f, 0xb5, 0xe7, 0x21, 0x32};
    CHECK((result->element == expected_element));
}
/*
TEST_CASE("SAECallback IgnoresNonSAEAuthFrames") {
    SAEPair result;
    atomic<bool> running{true};
    SAECallback callback{result, running};

    // Create a non-SAE authentication frame (algorithm=1 for Open System)
    vector<uint8_t> payload(6, 0);
    payload[0] = 0x01;  // Open System authentication
    payload[1] = 0x01;  // Sequence number
    
    RawPDU raw_pdu(payload);
    Dot11Authentication auth_pdu;
    auth_pdu.auth_algorithm(1);  // Open System (not SAE)
    auth_pdu.auth_seq_number(1);
    
    RadioTap radio;
    Dot11Beacon beacon;
    beacon.addr1("ff:ff:ff:ff:ff:ff");
    beacon.addr2("00:11:22:33:44:55");
    beacon.addr3("00:11:22:33:44:55");
    
    auto pdu = radio / beacon / auth_pdu / raw_pdu;
    
    // Test the callback
    bool should_continue = callback(pdu);
    
    // Should not process non-SAE frames
    CHECK((result.success == false));
    CHECK((result.scalar.empty()));
    CHECK((result.element.empty()));
    CHECK((should_continue == true));
}

TEST_CASE("SAECallback IgnoresWrongSequence") {
    SAEPair result;
    atomic running{true};
    SAECallback callback{result, running};

    // Create SAE auth frame with wrong sequence number
    vector<uint8_t> payload(98, 0);
    payload[0] = 0x03;  // SAE algorithm
    payload[1] = 0x02;  // Wrong sequence number (should be 1)
    
    RawPDU raw_pdu(payload);
    Dot11Authentication auth_pdu;
    auth_pdu.auth_algorithm(3);  // SAE
    auth_pdu.auth_seq_number(2); // Wrong sequence
    
    RadioTap radio;
    Dot11Beacon beacon;
    beacon.addr1("ff:ff:ff:ff:ff:ff");
    beacon.addr2("00:11:22:33:44:55");
    beacon.addr3("00:11:22:33:44:55");
    
    auto pdu = radio / beacon / auth_pdu / raw_pdu;
    
    // Test the callback
    bool should_continue = callback(pdu);
    
    // Should not process frames with wrong sequence
    CHECK((result.success == false));
    CHECK(result.scalar.empty());
    CHECK(result.element.empty());
    CHECK((should_continue == true));
}

TEST_CASE("SAECallback HandlesShortPayload") {
    SAEPair result;
    atomic running{true};
    SAECallback callback{result, running};

    // Create SAE auth frame with too short payload
    vector<uint8_t> payload(10, 0);  // Too short (need at least 98 bytes)
    payload[0] = 0x03;  // SAE algorithm
    payload[1] = 0x01;  // Correct sequence
    
    RawPDU raw_pdu(payload);
    Dot11Authentication auth_pdu;
    auth_pdu.auth_algorithm(3);  // SAE
    auth_pdu.auth_seq_number(1); // Correct sequence
    
    RadioTap radio;
    Dot11Beacon beacon;
    beacon.addr1("ff:ff:ff:ff:ff:ff");
    beacon.addr2("00:11:22:33:44:55");
    beacon.addr3("00:11:22:33:44:55");


    auto pdu = radio / beacon / auth_pdu / raw_pdu;
    // Test the callback
    bool should_continue = callback(pdu);
    
    // Should not process frames with insufficient payload
    CHECK((result.success == false));
    CHECK(result.scalar.empty());
    CHECK(result.element.empty());
    CHECK((should_continue == true));
}*/
