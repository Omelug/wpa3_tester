#pragma once
#include <vector>
#include "../tshark_wrapper.h"

namespace wpa3_tester{
    void add_graph_elements(std::vector<std::unique_ptr<GraphElements>>& elements);
}