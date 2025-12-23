#pragma once
#include <map>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>

class Actor_config {
public:
	Actor_config(const nlohmann::json& j);
	bool matches(const Actor_config &offer);
	std::optional<std::string>	iface;
    std::optional<std::string>	mac;
    std::optional<std::string>	essid;

	std::map<std::string, std::optional<bool>> bool_conditions = {
        {"monitor", std::nullopt},
        {"2_4Gz", std::nullopt},
        {"5GHz", std::nullopt},
        {"WPA-PSK", std::nullopt},
        {"WPA3-SAE", std::nullopt}
	};
};

