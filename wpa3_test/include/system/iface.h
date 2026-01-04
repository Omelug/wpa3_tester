#pragma once

#include <string>
#include <optional>
#include <vector>

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
};


