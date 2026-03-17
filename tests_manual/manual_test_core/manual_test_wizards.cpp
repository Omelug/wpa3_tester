#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

#include "config/RunStatus.h"
#include "system/hw_capabilities.h"
#include "manual_test_wizards.h"

#include "setup/scan.h"

namespace wpa3_tester::manual_tests {
    using namespace std;
    using namespace filesystem;

    void cli_section(const string& section_title){
        cout << "\n========================================\n";
        cout << "  " << section_title <<" \n";
        cout << "========================================\n\n";
    }

    unique_ptr<string> get_iface_wizard() {
        cli_section("WiFi Interface Selection");

        // List available WiFi interfaces
        cout << "Scanning for available WiFi interfaces...\n\n";
        auto interfaces = hw_capabilities::list_interfaces();
        vector<string> wifi_interfaces;

        cout << "Available WiFi interfaces:\n";
        cout << left << setw(5) << "No."
             << setw(20) << "Interface"
             << setw(20) << "Type" << "\n";
        cout << string(45, '-') << "\n";

        int index = 1;
        for (const auto& [iface_name, radio_name, iface_type] : interfaces) {
            if (iface_type == InterfaceType::Wifi ||
                iface_type == InterfaceType::WifiVirtualMon) {
                cout << left << setw(5) << index
                     << setw(20) << iface_name
                     << setw(20) << iface_to_string(iface_type) << "\n";
                wifi_interfaces.push_back(iface_name);
                index++;
            }
        }

        if (wifi_interfaces.empty()) {throw manual_test_err("No WiFi interfaces found!");}

        // Prompt user to select interface
        cout << "\nSelect an interface (enter number or name): ";
        string input;
        getline(cin, input);

        if (input.empty()) { throw manual_test_err("Selection cancelled.");}

        string selected_iface;
        try {
            // Try parsing as number
            int selection = stoi(input);
            if (selection < 1 || selection > static_cast<int>(wifi_interfaces.size())) {
                throw manual_test_err("Invalid selection!");
            }
            selected_iface = wifi_interfaces[selection - 1];
        } catch (...) {
            // Treat as interface name
            selected_iface = input;

            // Verify it exists in the list
            bool found = false;
            for (const auto& iface : wifi_interfaces) {
                if (iface == selected_iface) {
                    found = true;
                    break;
                }
            }
            if (!found) {throw manual_test_err("Interface '"+selected_iface+"' not found in available WiFi ifaces!");}
        }

        cout << "Selected interface: " << selected_iface << "\n\n";
        return std::make_unique<std::string>(selected_iface);
    }

    void print_external_entities(const vector<ActorPtr>& entities) {
        if (entities.empty()) {
            cout << "No entities found!\n";
            cout << "\nPossible reasons:\n";
            cout << "  - No WiFi activity in range\n";
            cout << "  - Interface not in proper mode\n";
            cout << "  - Scan duration too short\n";
            return;
        }

        // Separate APs and STAs
        vector<ActorPtr> aps;
        vector<ActorPtr> stas;

        for (const auto& entity : entities) {
            if (entity->get_bool("AP")) { aps.push_back(entity);
            } else { stas.push_back(entity);}
        }

        Actor_config::print_ActorCMap("Access points", aps);
        Actor_config::print_ActorCMap("Stations:", stas);

        cout << "\n========================================\n";
        cout << "Total entities found: " << entities.size()
             << " (" << aps.size() << " APs, " << stas.size() << " STAs)\n";
        cout << "========================================\n\n";
    }
    bool ask_ok(const std::string& question) {
        std::string input;
        do {
            std::cout << question << " (y/n): ";
            std::getline(std::cin, input);
            if (input == "ok" || input == "OK") return true;
            if (input == "y" || input == "Y") return true;
            if (input == "n" || input == "N") return false;
        } while (true);
    }
    ActorPtr wb_actor_selection(){
        cout << "\nThis test need OpenWrt devices defined in connection table" << endl;
        const path conn_table_path = absolute(path(PROJECT_ROOT_DIR) / "attack_config" /
                                                          "example_whitebox_table.csv");

        cout << "Using connection table: " << conn_table_path << endl;
        vector<ActorPtr> actors = scan::get_actors_conn_table(conn_table_path);
        if (actors.empty()){throw manual_test_err("ERROR: No actors found in connection table, test cant be run");}
        cout << "\nFound " << actors.size() << " actor(s) in connection table:" << endl;

        for (size_t i = 0; i < actors.size(); ++i) {
            const auto& actor = actors[i];
            cout << "  [" << i << "] ";
            if (actor->str_con["whitebox_host"].has_value()) {
                cout << actor->str_con["whitebox_host"].value();
            } else {
                cout << "Actor_" << i;
            }
            cout << " "<< actor->to_str() << endl;
            cout << endl;
        }

        // Select actor
        size_t selected_idx = 0;
        if (actors.size() > 1) {
            cout << "\nSelect actor index [0-" << (actors.size() - 1) << "]: ";
            cin >> selected_idx;
            if (selected_idx >= actors.size()) {throw manual_test_err("ERROR: Invalid actor index");}
        }
        return actors[selected_idx];
    }

    std::string get_openwrt_iface_wizard(OpenWrtConn* conn) {
        cli_section("OpenWrt Interface Selection for Tcpdump");

        const string output = conn->exec("ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://'");
        vector<string> ifaces;
        stringstream ss(output);
        string line;
        while (getline(ss, line)) {
            ifaces.push_back(line);
        }

        if (ifaces.empty()) {
            cout << "No interfaces found!" << endl;
            return "";
        }

        cout << "Available interfaces on OpenWrt:" << endl;
        for (size_t i = 0; i < ifaces.size(); ++i) {
            cout << "  [" << i << "] " << ifaces[i] << endl;
        }

        cout << "\nSelect interface index [0-" << (ifaces.size() - 1) << "]: ";
        size_t idx;
        cin >> idx;
        if (idx >= ifaces.size()) {
            cout << "Invalid index" << endl;
            return "";
        }
        return ifaces[idx];
    }
}
