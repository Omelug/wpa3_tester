#include "suite/suite_helper.h"

#include <fstream>
#include "default.h"
#include "config/RunStatus.h"

namespace wpa3_tester::suite::helper {
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

optional<json> load_result_json(const path &test_folder) {
	const auto result_json = test_folder / RESULT_NAME;
	if(!exists(result_json)) return nullopt;
	ifstream rf(result_json);
	return json::parse(rf);
}

}