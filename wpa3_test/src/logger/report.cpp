#include "logger/report.h"

#include "logger/log.h"
#include "suite/suite_helper.h"
#include "system/utils.h"

namespace wpa3_tester::report{
using namespace std;
using namespace filesystem;


ofstream open_report(const path &report_path){
	const path resolved = is_directory(report_path) ? report_path / REPORT_NAME : report_path;
	ofstream report(resolved);
	if(!report.is_open()) log(LogLevel::ERROR, "Failed to create report: {}", resolved);
	return report;
}

void finalize_report(ofstream &report, const path &run_dir){
	report.close();
	set_public_perms(run_dir / REPORT_NAME);
	log(LogLevel::INFO, "Report written: {}", run_dir / REPORT_NAME);
}

void attack_config_table(ReportGuard &report, const RunStatus &rs){
	auto attack_cfg = rs.config().at("attack_config");
	//report << "###### Attack Configuration\n\n";
	for(auto &[key, value]: attack_cfg.items()){
		report << "- **" << key << "**: " << value << "\n";
	}
	report << "\n";
}

void attack_mapping_table(ReportGuard &report, const RunStatus &rs){
	auto mapping = rs.run_folder() / "mapping.csv";

	ifstream csv_file(mapping);
	if(!csv_file.is_open()){
		log(LogLevel::WARNING, "Mapping file not found: {}", mapping.string());
		return;
	}

	//report << "#### Actor/Interface Mapping\n\n"
	report << "| Type | Actor Name | Interface | MAC | Driver |\n" <<
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

string device(Tins::HWAddress<6> mac){
	//TODO get mac[link to device] --markdown
	return mac;
}
//?TODO add object to << link with empty run_dir -> relative path set by gurd
string link(string text, const path &link_path, const optional<path> &run_dir){
	if(exists(link_path)){
		const string href = run_dir
			? link_path.lexically_relative(*run_dir).string()
			: link_path.string();
		return "["+text+"]("+href+")";
	}
	return text;
}
}
