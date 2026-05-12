#include "logger/report.h"

#include "logger/log.h"

namespace wpa3_tester::report{
using namespace std;
using namespace filesystem;

void attack_config_table(ofstream &report, const RunStatus &rs){
	auto attack_cfg = rs.config().at("attack_config");
	report << "## Attack Configuration\n\n";
	for(auto &[key, value]: attack_cfg.items()){
		report << "- **" << key << "**: " << value << "\n";
	}
	report << "\n";
}

void attack_mapping_table(ofstream &report, const RunStatus &rs){
	auto mapping = rs.run_folder() / "mapping.csv";

	ifstream csv_file(mapping);
	if(!csv_file.is_open()){
		log(LogLevel::WARNING, "Mapping file not found: {}", mapping.string());
		return;
	}

	report << "## Actor/Interface Mapping\n\n" << "| Type | Actor Name | Interface | MAC | Driver |\n" <<
			"|------|------------|-----------|-----|--------|\n";

	string line;
	getline(csv_file, line);

	while(getline(csv_file, line)){
		if(line.empty()) continue;

		stringstream ss(line);
		string type, actor_name, interface, mac, driver;

		getline(ss, type, ',');
		getline(ss, actor_name, ',');
		getline(ss, interface, ',');
		getline(ss, mac, ',');
		getline(ss, driver, ',');

		report << "| " << type << " | " << actor_name << " | " << interface << " | " << mac << " | " << driver <<
				" |\n";
	}

	report << "\n";
}
}
