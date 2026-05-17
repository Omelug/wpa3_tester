#pragma once
#include <array>
#include <nl80211.h>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include "actor_keys.h"
#include "system/hw_info.h"
#include "system/wifi_channel.h"
#include <tins/tins.h>

namespace wpa3_tester{

inline auto MONITOR_IFACE_PREFIX = std::string("mon_");
inline auto AP_IFACE_PREFIX      = std::string("ap_");
inline auto HWSIM_IFACE_PREFIX   = std::string("hwsim_");

class RunStatus;
class ExternalConn;

class Actor_config : public std::enable_shared_from_this<Actor_config> {
private:
	Driver _driver{};
	std::optional<Tins::HWAddress<6>> _mac;
	std::optional<Tins::HWAddress<6>> _permanent_mac;
public:
	[[nodiscard]] std::string operator[](const std::string &key) const;
	explicit Actor_config() = default;
    Actor_config(const Actor_config &other) = default;
    explicit Actor_config(const nlohmann::json &j);
    ~Actor_config();

    bool matches(const Actor_config &offer);
    Actor_config &operator+=(const Actor_config &other);
	void set(SK key, const std::optional<std::string> &new_value);
	void set(BK key, const std::optional<bool> &new_value);

	std::shared_ptr<ExternalConn> conn;

	[[nodiscard]] std::optional<std::string>&       operator[](SK key);
    [[nodiscard]] const std::optional<std::string>& operator[](SK key) const;
    [[nodiscard]] std::optional<bool>&              operator[](BK key);
    [[nodiscard]] const std::optional<bool>&        operator[](BK key) const;

	[[nodiscard]] std::string get(SK key) const;
	[[nodiscard]] bool        get(BK key) const;

    std::string        to_str()  const;
    nlohmann::json     to_json() const;

    // Serialize/deserialize BK bool fields as a flat {"ap": true, "monitor": false, ...} object
    nlohmann::json caps_to_flat_json() const;
    void           caps_from_flat_json(const nlohmann::json &j);

    static void print_ActorCMap(const std::string &title, const std::vector<ActorPtr> &actors);
    static void print_ActorCMap(const std::string &title, ActorCMap actors);

    [[nodiscard]] bool is_WB()          const;
    [[nodiscard]] bool is_external_WB() const;

    // Interface control
    int  run(const std::vector<std::string> &argv) const;
    void cleanup()          const;
    void create_sniff_iface() const;

    std::string get_driver_name() const;
    void load_hw_info(const std::optional<std::filesystem::path> &cache = std::nullopt);
    void set_channel(Channel ch, const std::string &ht_mode = "") const;
    void set_ap_mode()       const;
    void set_iface_down()    const;
    void set_iface_up()      const;
    void up_sniff_iface()    const;
    void set_managed_mode()  const;
    void set_mac_address(const Tins::HWAddress<6> &mac) const;
    void set_monitor_mode() const;
    void set_wifi_type(nl80211_iftype type) const;
    void set_mac(const std::string &mac_address);
    void set_permanent_mac(const std::string &mac_address);
    Channel get_channel() const;
    void setup_actor(const nlohmann::json &config, const ActorPtr &real_actor);

private:
	std::array<std::optional<std::string>, static_cast<std::size_t>(SK::COUNT_)> str_vals{};
	std::array<std::optional<bool>,static_cast<std::size_t>(BK::COUNT_)> bool_vals{};


    void setup_actor_internal(const nlohmann::json &config);
    void setup_actor_external_whitebox(const nlohmann::json &config, const ActorPtr &real_actor);
};

}
