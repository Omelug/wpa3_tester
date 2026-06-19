#pragma once
#include <array>
#include <nl80211.h>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <tins/tins.h>
#include "actor_keys.h"
#include "system/hw_info.h"
#include "system/wifi_channel.h"

namespace wpa3_tester{
enum class Source{ SIMULATION, INTERNAL, EXTERNAL };

inline auto MONITOR_IFACE_PREFIX = std::string("mon_");
inline auto AP_IFACE_PREFIX = std::string("ap_");
inline auto HWSIM_IFACE_PREFIX = std::string("hwsim_");

class RunStatus;
class ExternalConn;

class Actor_config: public std::enable_shared_from_this<Actor_config>{
	Driver _driver{};
public:
	[[nodiscard]] std::string operator[](const std::string &key) const;
	explicit Actor_config() = default;
	Actor_config(const Actor_config &other) = default;
	explicit Actor_config(const nlohmann::json &j, std::string source = "");
	virtual ~Actor_config();

	bool matches(const Actor_config &offer) const;
	Actor_config &operator+=(const Actor_config &other);
	void set(SK key, const std::optional<std::string> &new_value);
	void set(BK key, const std::optional<bool> &new_value);

	//to allow HWAddress -> simplify code
	struct MacSK{
		SK key;
		// ReSharper disable once CppNonExplicitConvertingConstructor
		consteval MacSK(const SK k): key(k){
			if(k != SK::mac && k != SK::permanent_mac){
				throw "Only SK::mac or SK::permanent_mac!";
			}
		}
	};

	void set(const MacSK key, const Tins::HWAddress<6> &addr){
		set(key.key, addr.to_string());
	}

	std::shared_ptr<ExternalConn> conn;

	[[nodiscard]] std::optional<std::string> &operator[](SK key);
	[[nodiscard]] const std::optional<std::string> &operator[](SK key) const;
	[[nodiscard]] std::optional<bool> &operator[](BK key);
	[[nodiscard]] const std::optional<bool> &operator[](BK key) const;

	[[nodiscard]] std::string get(SK key) const;
	[[nodiscard]] bool get(BK key) const;
	[[nodiscard]] std::string get_or(SK key, std::string default_val) const;
	[[nodiscard]] bool get_or(BK key, bool default_val) const;

	std::string to_str(const ParamFilter *filter = nullptr) const;
	nlohmann::json to_json(const ParamFilter *filter = nullptr) const;

	// Serialize/deserialize BK bool fields as a flat {"ap": true, "monitor": false, ...} object
	nlohmann::json hw_info_caps_to_flat_json() const;
	void caps_from_flat_json(const nlohmann::json &j);

	static void print_ActorCMap(const std::string &title, const std::vector<ActorPtr> &actors);
	static void print_ActorCMap(const std::string &title, const ActorCMap &actors);

	[[nodiscard]] bool is_WB() const;
	[[nodiscard]] bool is_external_WB() const;
	[[nodiscard]] bool monitor_needed() const;
	Channel get_channel() const;

	// Interface control
	int run(const std::vector<std::string> &argv, bool print = true) const;
	virtual void cleanup() const;
	virtual void create_sniff_iface() const;

	std::string get_driver_name() const;
	void load_hw_info(const std::optional<std::filesystem::path> &cache = std::nullopt);
	virtual void set_channel(const Channel &ch) const;
	virtual void set_ap_mode() const;
	virtual void set_iface_down() const;
	virtual void set_iface_up() const;
	virtual void up_sniff_iface() const;
	virtual void set_managed_mode() const;
	virtual void set_mac_address(const Tins::HWAddress<6> &mac) const;
	virtual void set_monitor_mode() const;
	void set_wifi_type(nl80211_iftype type, const std::vector<std::string> &monitor_flags = {}) const;

	virtual void setup_actor(const nlohmann::json &, const ActorPtr &);

	static std::shared_ptr<Actor_config> create(const nlohmann::json &j);
private:
	std::array<std::optional<std::string>,static_cast<std::size_t>(SK::COUNT_)> str_vals{};
	std::array<std::optional<bool>,static_cast<std::size_t>(BK::COUNT_)> bool_vals{};
};
}
