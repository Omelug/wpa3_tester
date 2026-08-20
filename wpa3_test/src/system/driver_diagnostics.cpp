#include "system/driver_diagnostics.h"

#include "system/hw_capabilities.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <system_error>

#include <nlohmann/json_fwd.hpp>

namespace wpa3_tester::driver_diag{
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

namespace{

// debugfs stat dumps are small, limit for errors
constexpr size_t MAX_TEXT_FILE_BYTES = 8192;

bool dir_exists(const path &p){
	error_code ec;
	return exists(p, ec) && !ec;
}

// reads a text debugfs file
// returns nullopt if missing/unreadable
// (wrong permissions, file doesn't exist on this kernel/driver version, etc).
optional<string> read_file(const path &p){
	if(!dir_exists(p)) return nullopt;
	ifstream f(p, ios::binary);
	if(!f.is_open()) return nullopt;

	string data(MAX_TEXT_FILE_BYTES, '\0');
	f.read(data.data(), static_cast<streamsize>(data.size()));
	data.resize(static_cast<size_t>(f.gcount()));
	return data;
}


// lists filenames (not full paths)
// empty on error
vector<string> list_dir(const path &dir){
	vector<string> out;
	error_code ec;
	if(!dir_exists(dir)) return out;
	for(const auto &entry: directory_iterator(dir, ec)){
		if(ec) break;
		out.push_back(entry.path().filename().string());
	}
	return out;
}

// locates <debugfs>/ieee80211/phyN/<subdir>
// `phy` may come back from hw_capabilities::get_phy() as "phy1" or just "1"
path phy_debugfs_dir(const string &phy, const string &subdir){
	string phy_name = phy;
	if(phy_name.rfind("phy", 0) != 0) phy_name = "phy" + phy_name;
	return path("/sys/kernel/debug/ieee80211") / phy_name / subdir;
}

string to_lower(string s){ //FIXME needed?
	ranges::transform(s, s.begin(), [](const unsigned char c){ return static_cast<char>(tolower(c)); });
	return s;
}

// mt76 family (mt76x0/mt76x2/mt7615/mt7915/..

// mt76 core - queues, rx-queues, regidx/regval, napi_threaded, eeprom
// from mt76_register_debugfs_fops();
// https://github.com/openwrt/mt76/blob/master/debugfs.c

// mt76x02/mt76x2e lib - ampdu_stat/dfs_stats/txpower/temperature/tpc
// https://github.com/openwrt/mt76/blob/master/mt76x02_debugfs.c
// https://github.com/openwrt/mt76/blob/master/mt76x2/debugfs.c
json collect_mt76(const string &phy){
	json j;
	const path dir = phy_debugfs_dir(phy, "mt76");
	const bool present = dir_exists(dir);
	j["debugfs_dir"] = dir.string();
	j["present"] = present;
	if(!present) return j;
	if(auto v = read_file(dir / "xmit-queues"))   j["tx_queues"] = *v;
	if(auto v = read_file(dir / "rx-queues"))     j["rx_queues"] = *v;
	if(auto v = read_file(dir / "ampdu_stat"))    j["ampdu_stat"] = *v;
	if(auto v = read_file(dir / "dfs_stats"))     j["dfs_stats"] = *v;
	if(auto v = read_file(dir / "txpower"))       j["txpower"] = *v;
	if(auto v = read_file(dir / "rate_txpower"))  j["rate_txpower"] = *v;
	// avg_rssi_all, low_gain, false_cca, agc_gain_adjust
	if(auto v = read_file(dir / "agc"))           j["agc"] = *v;
	// energy-detect CCA monitor state
	if(auto v = read_file(dir / "edcca"))         j["edcca"] = *v;
	if(auto v = read_file(dir / "temperature"))   j["temperature_raw"] = *v;
	if(auto v = read_file(dir / "tpc"))           j["tpc_enabled"] = *v;
	if(auto v = read_file(dir / "tx_hang_reset")) j["tx_hang_reset"] = *v;
	// regidx/regval let you peek an arbitrary MAC/BBP register by address, but
	// writing regidx first is required to select *which* register regval then
	// shows - not meaningful to dump blindly, so we only report availability.
	j["reg_peek_available"] = dir_exists(dir / "regidx") && dir_exists(dir / "regval");
	j["available_files"] = list_dir(dir);
	return j;
}

// ath9k_htc
// much smaller file set than plain PCIe ath9k ( .../phyX/ath9k/)
// USB target runs its own firmware ->  firmaware uploaded as is during init
// CONFIG_ATH9K_HTC_DEBUGFS

// https://wireless.docs.kernel.org/en/latest/en/users/drivers/ath9k/debug.html
// https://github.com/torvalds/linux/blob/master/drivers/net/wireless/ath/ath9k/htc_drv_debug.c
// (debugfs dir is created as KBUILD_MODNAME, i.e. "ath9k_htc", under wiphy->debugfsdir)
json collect_ath9k_htc(const string &phy){
	json j;
	const path dir = phy_debugfs_dir(phy, "ath9k_htc");
	const bool present = dir_exists(dir);
	j["debugfs_dir"] = dir.string();
	j["present"] = present;
	if(!present) return j;

	if(auto v = read_file(dir / "tgt_tx_stats"))  j["target_tx_stats"] = *v;
	if(auto v = read_file(dir / "tgt_rx_stats"))  j["target_rx_stats"] = *v;
	if(auto v = read_file(dir / "tgt_int_stats")) j["target_interrupt_stats"] = *v;
	if(auto v = read_file(dir / "xmit"))          j["host_tx_stats"] = *v;
	if(auto v = read_file(dir / "recv"))          j["host_rx_stats"] = *v;
	if(auto v = read_file(dir / "slot"))          j["host_slot_stats"] = *v;
	if(auto v = read_file(dir / "queue"))         j["host_queue_stats"] = *v;
	if(auto v = read_file(dir / "debug"))         j["debug_mask"] = *v;
	j["available_files"] = list_dir(dir);
	return j;
}

// rtw88 family
// Covers rtl8821cu
// USB support (rtw_8821cu + rtw_usb glue) from kernel 6.2

// Requires kernel config CONFIG_RTW88_DEBUGFS
// https://patchwork.kernel.org/project/linux-wireless/patch/1542094341-8060-9-git-send-email-yhchuang@realtek.com/
// https://lore.kernel.org/linux-wireless/20210802063140.25670-4-pkshih@realtek.com/
// https://github.com/lwfinger/rtw88
json collect_rtw88(const string &phy){
	json j;
	const path dir = phy_debugfs_dir(phy, "rtw88");
	const bool present = dir_exists(dir);
	j["debugfs_dir"] = dir.string();
	j["present"] = present;
	if(!present) return j;
	if(auto v = read_file(dir / "rf_dump"))      j["rf_dump"] = *v;
	if(auto v = read_file(dir / "tx_pwr_tbl"))   j["tx_power_table"] = *v;
	if(auto v = read_file(dir / "coex_info"))    j["coex_info"] = *v;
	// per-path RSSI/EVM/SNR/CFO
	if(auto v = read_file(dir / "phy_info"))     j["phy_info"] = *v;
	if(auto v = read_file(dir / "dm_cap"))       j["dm_cap"] = *v;
	// energy-detect CCA, same relevance as mt76's edcca
	if(auto v = read_file(dir / "edcca_enable")) j["edcca_enable"] = *v;
	// programmed per-station security keys
	if(auto v = read_file(dir / "dump_cam"))     j["dump_cam"] = *v;
	if(auto v = read_file(dir / "rsvd_page"))    j["rsvd_page"] = *v; // firmware beacon/probe-resp template buffer
	// fw_crash is a *control* file
	// write to it to trigger a simulated firmware crash for SER recovery testing
	// only reported as available
	j["fw_crash_control_available"] = dir_exists(dir / "fw_crash");
	j["h2c_control_available"] = dir_exists(dir / "h2c");
	j["available_files"] = list_dir(dir);
	return j;
}

// rtw89 family
// NOTE: mainline USB support (CONFIG_RTW89_8852AU) only appears in very recent kernel series
// (including Kali) rtl8852au most likely still runs the out-of-tree
// morrownr/rtw89 (or lwfinger/rtw89) DKMS driver instead of the in-tree one
// That out-of-tree driver tracks the same upstream debug.c fairly closely

// debugfs root: /sys/kernel/debug/ieee80211/phyX/rtw89/
// CONFIG_RTW89_8852AU
// https://cateee.net/lkddb/web-lkddb/RTW89_8852AU.html
// https://github.com/morrownr/rtw89
// https://deepwiki.com/pkshih/rtw89-test/9-debug-and-diagnostics
json collect_rtw89(const string &phy){
	json j;
	const path dir = phy_debugfs_dir(phy, "rtw89");
	const bool present = dir_exists(dir);
	j["debugfs_dir"] = dir.string();
	j["present"] = present;
	if(!present) return j;

	if(auto v = read_file(dir / "phy_info"))    j["phy_info"] = *v;
	if(auto v = read_file(dir / "btc_info"))    j["bt_coex_info"] = *v;
	if(auto v = read_file(dir / "stations"))    j["stations"] = *v;
	if(auto v = read_file(dir / "txpwr_table")) j["tx_power_table"] = *v;
	// control file, see rtw88 note above
	j["fw_crash_control_available"] = dir_exists(dir / "fw_crash");
	j["available_files"] = list_dir(dir);
	return j;
}

// rtl8xxxu

// debugfs is genuinely minimal-only registers a single "efuse" blob (raw NVM/calibration dump)

// https://wireless.docs.kernel.org/en/latest/en/users/drivers/rtl819x.html
// https://github.com/torvalds/linux/blob/master/drivers/net/wireless/realtek/rtl8xxxu/core.c
json collect_rtl8xxxu(const string &phy){
	json j;
	const path dir = phy_debugfs_dir(phy, "rtl8xxxu");
	const bool present = dir_exists(dir);
	j["debugfs_dir"] = dir.string();
	j["present"] = present;
	if(!present) return j;

	j["efuse_blob_available"] = dir_exists(dir / "efuse"); // raw binary NVM dump, deliberately not read as text
	j["available_files"] = list_dir(dir);
	j["note"] = "rtl8xxxu debugfs is minimal upstream (efuse dump only); "
				"most useful diagnostics for this chip come from ethtool -S / dmesg instead.";
	return j;
}

}

json collect_driver_specific(const string &driver_name, const string &phy){
	json j;
	j["driver_name"] = driver_name;
	j["phy"] = phy;

	try{
		if(phy.empty()){
			j["error"] = "phy unknown, cannot locate debugfs directory";
			return j;
		}

		const string d = to_lower(driver_name);

		if(d.find("mt76") != string::npos){
			j["family"] = "mt76";
			j["mt76"] = collect_mt76(phy);
		} else if(d.find("ath9k_htc") != string::npos){
			j["family"] = "ath9k_htc";
			j["ath9k_htc"] = collect_ath9k_htc(phy);
		} else if(d.find("rtw89") != string::npos || d.find("8852a") != string::npos ||
				d.find("8852b") != string::npos || d.find("8852c") != string::npos){
			j["family"] = "rtw89";
			j["rtw89"] = collect_rtw89(phy);
		} else if(d.find("rtw88") != string::npos || d.find("rtw_") != string::npos ||
				d.find("8821c") != string::npos || d.find("8822b") != string::npos ||
				d.find("8822c") != string::npos || d.find("8723d") != string::npos){
			j["family"] = "rtw88";
			j["rtw88"] = collect_rtw88(phy);
		} else if(d.find("rtl8xxxu") != string::npos || d.find("8192cu") != string::npos){
			j["family"] = "rtl8xxxu" ;
			j["rtl8xxxu"] = collect_rtl8xxxu(phy);
		} else{ // Unrecognised driver -> not guess a subdirectory name
			j["family"] = "unknown";
			const path phy_root = path("/sys/kernel/debug/ieee80211") /
				(phy.rfind("phy", 0) == 0 ? phy : "phy" + phy);
			j["phy_debugfs_root"] = phy_root.string();
			j["available_subdirs"] = list_dir(phy_root);
		}
	} catch(const exception &e){
		j["error"] = string("driver_specific collection failed: ") + e.what();
	}

	return j;
}

json collect_regulatory(const string &phy, const optional<string> &netns) {
	json j;
	try{ j["iw_reg_get"] = hw_capabilities::run_cmd_output({"iw", "reg", "get"}, netns); } catch(...){}
	if(!phy.empty()){
		const string phy_name = phy.rfind("phy", 0) == 0 ? phy : "phy" + phy;
		try{ j["phy_reg_get"] = hw_capabilities::run_cmd_output({"iw", "phy", phy_name, "reg", "get"}, netns); } catch(...){}
		if(auto v = read_file(phy_debugfs_dir(phy, "") / "regdom")) j["debugfs_regdom"] = *v;
	}
	return j;
}

//  --------- USB device info

static string trim_ws(string s){
	const auto last = s.find_last_not_of(" \t\n\r\f\v");
	return last == string::npos ? "" : s.substr(0, last + 1);
}

json collect_usb_info(const string &iface){
	json j;
	const path net_dev = path("/sys/class/net") / iface / "device";
	if(!dir_exists(net_dev)){ j["is_usb"] = false; return j; }

	// walk up sysfs to find USB device dir (has idVendor)
	error_code ec;
	const path real = canonical(net_dev, ec);
	if(ec){ j["is_usb"] = false; return j; }

	for(path p = real; p != p.root_path(); p = p.parent_path()){
		if(!dir_exists(p / "idVendor")) continue;
		j["is_usb"] = true;
		j["usb_path"] = p.string();
		if(auto v = read_file(p / "idVendor"))    j["id_vendor"]    = trim_ws(*v);
		if(auto v = read_file(p / "idProduct"))   j["id_product"]   = trim_ws(*v);
		if(auto v = read_file(p / "manufacturer")) j["manufacturer"] = trim_ws(*v);
		if(auto v = read_file(p / "product"))      j["product"]      = trim_ws(*v);
		if(auto v = read_file(p / "serial"))       j["serial"]       = trim_ws(*v);
		if(auto v = read_file(p / "authorized"))   j["authorized"]   = trim_ws(*v) == "1";
		return j;
	}
	j["is_usb"] = false;
	return j;
}

bool is_meta_key(const string &key){
	return key == "debugfs_dir" || key == "present" || key == "available_files" ||
		key == "note" || key.ends_with("_available");
}

string summarize_driver_specific(const json &ds){
	if(ds.is_null() || ds.empty()) return "n/a";
	if(ds.contains("error")) return "error: " + ds.value("error", "");

	const string family = ds.value("family", "unknown");
	const string driver_name = ds.value("driver_name", "?");

	if(family == "unknown"){
		const size_t n = ds.value("available_subdirs", json::array()).size();
		return driver_name + " (unrecognised driver, " + to_string(n) + " debugfs subdir(s) seen)";
	}

	if(!ds.contains(family)) return family + " (no data)";
	const json &fam = ds.at(family);

	if(!fam.value("present", false)) return family + " (debugfs not found - need root / CONFIG_*_DEBUGFS?)";

	vector<string> fields;
	for(const auto &[key, value]: fam.items()){
		if(is_meta_key(key)) continue;
		fields.push_back(key);
	}

	if(fields.empty()) return family + " (present, no readable fields)";

	string out = family + ": ";
	for(size_t i = 0; i < fields.size(); ++i){
		if(i) out += ", ";
		out += fields[i];
	}
	return out;
}

}