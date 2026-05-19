#include "observer/graph/graph_utils.h"
#include <cstdio>
#include <vector>

#include "logger/error_log.h"
#include "observer/tshark_wrapper.h"
using namespace std;

namespace wpa3_tester{
void Graph::add_graph_elements(const vector<unique_ptr<GraphElements>> &elements){
	size_t label_index = 0;
	size_t block_index = 0;

	for(auto &element: elements){
		if(element->type == GraphElement_t::EVENT_LINES){
			add_event_lines(*static_cast<EventLines *>(element.get()), block_index, elements.size(), label_index);
		}
		if(element->type == GraphElement_t::GRAPH_XY_POINTS){
			add_XY_points(*static_cast<GraphXYPoints *>(element.get()));
		}
		if(element->type == GraphElement_t::UNKNOWN){
			throw run_err("Graph element type is unknown");
		}
	}
}
}