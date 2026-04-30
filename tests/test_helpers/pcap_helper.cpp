#include <vector>
#include <pcap/pcap.h>

using namespace std;
using namespace Tins;

namespace wpa3_tester::test_helpers{
// All frames from a pcap -> vector of raw byte vector
vector<vector<uint8_t>> read_all_frames(const string &path){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(path.c_str(), errbuf);
    if(!handle) throw runtime_error("pcap_open_offline failed: " + string(errbuf));

    vector<vector<uint8_t>> frames;
    pcap_pkthdr *hdr;
    const u_char *data;
    while(pcap_next_ex(handle, &hdr, &data) == 1) frames.emplace_back(data, data + hdr->caplen);

    pcap_close(handle);
    return frames;
}

// read
pair<pcap_pkthdr,vector<uint8_t>> read_one_frame(const string &path){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(path.c_str(), errbuf);
    if(!handle) throw runtime_error("pcap_open_offline failed: " + string(errbuf));

    pcap_pkthdr *hdr;
    const u_char *data;
    if(pcap_next_ex(handle, &hdr, &data) != 1){
        pcap_close(handle);
        throw runtime_error("No packets in file: " + path);
    }

    vector bytes(data, data + hdr->caplen);
    pcap_pkthdr copy = *hdr;
    pcap_close(handle);
    return {copy, bytes};
}

// read one frame from single pcap file
vector<uint8_t> read_pcap_file(const string &filename){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename.c_str(), errbuf);
    if(!handle) throw runtime_error("pcap_open_offline failed: " + string(errbuf));

    pcap_pkthdr *header;
    const u_char *packet;
    pcap_next_ex(handle, &header, &packet);
    vector frame_data(packet, packet + header->caplen);
    pcap_close(handle);
    return frame_data;
}
}
