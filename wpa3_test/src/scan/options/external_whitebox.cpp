#include <fstream>
#include <sstream>
#include "config/global_config.h"
#include "config/RunStatus.h"
#include "config/Actor_Config/Actor_Config_external.h"
#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "scan/scan.h"
#include "system/hw_capabilities.h"
#include "system/hw_info.h"
#include "system/ip.h"

namespace wpa3_tester{
using namespace std;
using nlohmann::json;
using namespace Tins;
using namespace filesystem;

namespace scan{

vector<string> parse_csv_line(const string &line){
	vector<string> fields;
	stringstream ss(line);
	string field;
	while(getline(ss, field, ',')){
		field.erase(0, field.find_first_not_of(" \t\r\n"));
		field.erase(field.find_last_not_of(" \t\r\n") + 1);
		fields.push_back(field);
	}
	return fields;
}

vector<ActorPtr> get_actors_conn_table(const path &conn_table){
	vector<ActorPtr> result;

	if(!exists(conn_table)){
		log(LogLevel::DEBUG, "Connection table file does not exist: {}", conn_table.string());
		return result;
	}

	ifstream file(conn_table);
	if(!file.is_open()){ throw scan_err("Failed to open connection table: {}", conn_table.string()); }
	string line;
	if(!getline(file, line)){ throw scan_err("Empty connection table: " + conn_table.string()); }

	// Parse header
	vector<string> headers = parse_csv_line(line);
	map<string,size_t> col_idx;
	for(size_t i = 0; i < headers.size(); ++i){ col_idx[headers[i]] = i; }

	// required columns
	if(!col_idx.contains("whitebox_host") || !col_idx.contains("whitebox_ip")){
		throw scan_err("Connection table missing required columns (whitebox_host, whitebox_ip): {}",
						conn_table.string());
	}

	while(getline(file, line)){
		if(line.empty()) continue;

		vector<string> fields = parse_csv_line(line);
		if(fields.empty()) continue;

		auto cfg = ActorPtr(make_shared<Actor_Config_external>());

		auto set_field = [&](const string &col_name, const SK &cfg_key){
			if(col_idx.contains(col_name) && col_idx[col_name] < fields.size()){
				const string &value = fields[col_idx[col_name]];
				if(!value.empty()){
					cfg[cfg_key] = value;
				}
			}
		};

		set_field("whitebox_host", SK::whitebox_host);
		set_field("whitebox_ip", SK::whitebox_ip);
		set_field("external_OS", SK::external_OS);
		set_field("ssh_user", SK::ssh_user);
		set_field("ssh_port", SK::ssh_port);
		set_field("ssh_password", SK::ssh_password);

		result.emplace_back(cfg);
	}

	log(LogLevel::INFO, "Loaded {} whitebox actors from connection table", result.size());
	return result;
}

}

void RunStatus::add_actors_by_radio(vector<ActorPtr> &options, const ActorPtr &cfg){
	//cfg->conn->ensure_wifi_ifaces();
	for(const auto radios = cfg->conn->get_radio_list(); const string &radio_name: radios){
		auto actor_cfg = ActorPtr(make_shared<Actor_Config_external>(*cfg));
		actor_cfg->set(SK::driver_name, cfg->conn->get_driver(radio_name));
		actor_cfg->set(SK::driver_hash, hw_capabilities::get_driver_hash(actor_cfg->get(SK::driver_name)));
		actor_cfg->set(SK::module_hash, hw_capabilities::get_module_hash(actor_cfg->get(SK::driver_name)));
		actor_cfg->set(SK::radio, radio_name);
		cfg->conn->get_hw_capabilities(*actor_cfg, radio_name);
		options.emplace_back(actor_cfg);
	}
}

// return <string radio_name; external_actor >
vector<ActorPtr> RunStatus::external_wb_options(){
	vector<ActorPtr> options;
	//option1: whitebox_host -> whitebox_ip
	const path conn_table = absolute(
		path(PROJECT_ROOT_DIR) / "attack_config" / get_global_config().at("actors").at("conn_table").get<string>());

	for(auto &cfg: scan::get_actors_conn_table(conn_table)){
		if(!cfg[SK::whitebox_ip].has_value()){
			const string ip_str = ip::resolve_host(cfg.get(SK::whitebox_host));
			cfg->set(SK::whitebox_ip, ip_str);
			log(LogLevel::DEBUG, "Resolved {} -> {}", cfg["whitebox_host"], ip_str.c_str());
		}
		const string ip = cfg.get(SK::whitebox_ip);
		if(!ip::ping(ip)){
			log(LogLevel::WARNING, "Actor {} not reachable, skipping", ip);
			continue;
		}
		get_or_create_connection(cfg);
		add_actors_by_radio(options, cfg);
	}
	return options;
}

}
