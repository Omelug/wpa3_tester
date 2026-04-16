#include "observer/grapth/graph_utils.h"
#include <cstdio>
#include <vector>

#include "observer/tshark_wrapper.h"
using namespace std;

namespace wpa3_tester{
    void Graph::add_graph_elements(const vector<unique_ptr<GraphElements>>& elements){

        size_t label_index = 0;
        size_t block_index = 0;

        for (auto& element : elements){
            if(element->type == GraphElement_t::EVENT_LINES){
                add_elements(*static_cast<EventLines*>(element.get()),
                    block_index, elements.size(), label_index);
            }
        }
    }
}