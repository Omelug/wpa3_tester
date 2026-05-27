#include "observer/graph/graph_utils.h"
#include <cstdio>
#include <map>
#include <vector>

#include "logger/error_log.h"
#include "observer/tshark_wrapper.h"
using namespace std;

namespace wpa3_tester{
void Graph::add_graph_elements(const vector<unique_ptr<GraphElements>> &elements){
	size_t label_index = 0;
	size_t block_index = 0;

	map<string, size_t> label_slots;
	for(auto &element: elements){
		if(element->type == GraphElement_t::EVENT_LINES){
			const string &lbl = static_cast<EventLines *>(element.get())->label;
			if(!label_slots.contains(lbl)){
				const size_t slot = label_slots.size();
				label_slots.emplace(lbl, slot);
			}
		}
	}
	const size_t num_slots = label_slots.empty() ? 1 : label_slots.size();

	for(auto &element: elements){
		if(element->type == GraphElement_t::EVENT_LINES){
			auto *ev = static_cast<EventLines *>(element.get());
			add_event_lines(*ev, block_index, label_slots.at(ev->label), num_slots, label_index);
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