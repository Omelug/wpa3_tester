#pragma once

#include <string>
#include <optional>
#include <vector>

namespace wpa3_tester{
    // class for working with
    class iface {
    public:
        void set_channel(int channel) const;
        void set_managed_mode() const;
        void set_monitor_mode() const;
        void cleanup() const;

        explicit iface(std::string name, std::optional<std::string> netns = std::nullopt);
        std::string name;
        std::optional<std::string> netns;

        int run(const std::vector<std::string> &argv) const;
        static bool is_physical_interface(const std::string& iface_name);
        //static std::string get_mac_address(const std::string& iface_name, const std::optional<std::string>& netns = std::nullopt);
        static std::string rand_mac();
    };
}

