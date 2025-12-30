#pragma once
#include <map>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>

class Actor_config {
public:
    explicit Actor_config(const nlohmann::json& j);
	bool matches(const Actor_config &offer);

    std::map<std::string, std::optional<std::string>> str_con = {
        {"iface",  std::nullopt},
        {"mac",    std::nullopt},
        {"essid",  std::nullopt},
        {"driver", std::nullopt}
    };

	std::map<std::string, std::optional<bool>> bool_conditions = {
        {"monitor", std::nullopt},
        {"2_4Gz", std::nullopt},
        {"5GHz", std::nullopt},
        {"WPA-PSK", std::nullopt},
        {"WPA3-SAE", std::nullopt}
	};
    std::string operator[](const std::string& key) const;
    bool get_bool(const std::string &key) const;
};
