#include "manuf_parser.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;

struct ManufEntry { uint64_t prefix48; int bits; string vendor; };

// returns prefix left-aligned in 48 bits;
// sets *out_parsed_bits = byte_count * 8
static uint64_t parse_prefix48(const string& s, int* out_parsed_bits) {
    uint64_t v = 0; int bytes = 0;
    const char* p = s.c_str();
    while (*p && bytes < 6) {
        char* end;
        v = (v << 8) | strtoul(p, &end, 16);
        ++bytes;
        p = (*end == ':') ? end + 1 : end;
    }
    *out_parsed_bits = bytes * 8;
    return v << (48 - *out_parsed_bits);
}

static vector<ManufEntry> load(const path& f) {
    vector<ManufEntry> out;
    ifstream in(f); if (!in) return out;
    string line;
    while (getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;

    	// format: MAC[/bits]\tShortName\tLongName ()
        auto t1 = line.find('\t');
        if (t1 == string::npos) continue;
        auto t2 = line.find('\t', t1 + 1);
        string mac_field = line.substr(0, t1);
        string vendor    = (t2 != string::npos) ? line.substr(t2 + 1) : line.substr(t1 + 1);
        while (!vendor.empty() && (vendor.back() == '\r' || vendor.back() == '\n')) vendor.pop_back();

        int explicit_bits = 0;
        auto slash = mac_field.find('/');
        if (slash != string::npos) {
            explicit_bits = stoi(mac_field.substr(slash + 1));
            mac_field.resize(slash);
        }
        int parsed;
        out.push_back({parse_prefix48(mac_field, &parsed), explicit_bits ? explicit_bits : parsed, std::move(vendor)});
    }
    // longest match first so the first hit is always the most specific
    ranges::sort(out, [](const ManufEntry& a, const ManufEntry& b){ return a.bits > b.bits; });
    return out;
}

string lookup_vendor(const path& manuf_file, const string& mac) {
    static const vector<ManufEntry> db = load(manuf_file);

    uint64_t target = 0;
    const char* p = mac.c_str();
    for (int i = 0; i < 6 && *p; ++i) {
        char* end;
        target = (target << 8) | strtoul(p, &end, 16);
        p = (*end == ':') ? end + 1 : end;
    }

    for (const auto& e : db) {
        if ((target >> (48 - e.bits)) == (e.prefix48 >> (48 - e.bits))) return e.vendor;
    }
    return {};
}

}
