#include <vector>
#include <pcap/pcap.h>

using namespace std;

namespace wpa3_tester::test_helpers{
vector<uint8_t> read_pcap_file(const string &filename){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename.c_str(), errbuf);
    pcap_pkthdr *header;
    const u_char *packet;
    pcap_next_ex(handle, &header, &packet);
    vector frame_data(packet, packet + header->caplen);
    pcap_close(handle);
    return frame_data;
}
}
