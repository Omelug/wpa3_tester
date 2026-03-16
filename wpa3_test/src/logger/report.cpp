#include "logger/report.h"

#include "logger/log.h"

namespace wpa3_tester::report{
    using namespace std;
    using namespace filesystem;

    void attack_config_table(std::ofstream& report, const RunStatus& rs){
        auto attack_cfg = rs.config.at("attack_config");
        report << "## Attack Configuration\n\n";
        for (auto& [key, value] : attack_cfg.items()) {
            report << "- **" << key << "**: " << value << "\n";
        }
        report << "\n";
    }

    void attack_mapping_table(std::ofstream& report, const RunStatus& rs){
        auto mapping = path(rs.run_folder) / "mapping.csv";

        if (!exists(mapping)) {
            log(LogLevel::WARNING, "Mapping file not found: "+mapping.string());
            return;
        }

        report << "## Actor/Interface Mapping\n\n";

        ifstream csv_file(mapping);
        if (!csv_file.is_open()) {
            log(LogLevel::ERROR, "Failed to open mapping file: "+mapping.string());
            return;
        }

        string line;
        bool is_header = true;

        while (getline(csv_file, line)) {
            if (line.empty()) continue;

            if (is_header) {
                // Convert CSV header to markdown table header
                report << "| Type | Actor Name | Interface | MAC | Driver |\n";
                report << "|------|------------|-----------|-----|--------|\n";
                is_header = false;
                continue;
            }

            // Parse CSV line and convert to markdown table row
            stringstream ss(line);
            string type, actor_name, interface, mac, driver;

            getline(ss, type, ',');
            getline(ss, actor_name, ',');
            getline(ss, interface, ',');
            getline(ss, mac, ',');
            getline(ss, driver, ',');

            report << "| " << type << " | " << actor_name << " | " << interface
                   << " | " << mac << " | " << driver << " |\n";
        }

        report << "\n";
        csv_file.close();
    }
}
