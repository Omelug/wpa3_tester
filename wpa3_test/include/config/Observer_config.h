#pragma once
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>

#include "RunStatus.h"

namespace wpa3_tester::observer{
    class Observer_config : public std::enable_shared_from_this<Observer_config>{
    public:
        std::string observer_name;
        const nlohmann::json& observer_config;
        explicit Observer_config(const nlohmann::json& observer_config): observer_config(observer_config){};
        int start(RunStatus &rs) const;
        std::string to_str() const;
    };
}
