#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>

#include "config/RunStatus.h"
#include "system/hw_capabilities.h"
#include "scan/scan.h"
#include "manual_test_wizards.h"

namespace wpa3_tester::manual_tests{
using namespace std;
using namespace filesystem;

void cli_section(const string &section_title){
    cout << "\n========================================\n";
    cout << "  " << section_title << " \n";
    cout << "========================================\n\n";
}

unique_ptr<string> get_iface_wizard(){
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
    for(const auto &[iface_name, radio_name, iface_type]: interfaces){
        if(iface_type == InterfaceType::Wifi ||
            iface_type == InterfaceType::WifiVirtualMon){
            cout << left << setw(5) << index
                    << setw(20) << iface_name
                    << setw(20) << iface_to_string(iface_type) << "\n";
            wifi_interfaces.push_back(iface_name);
            index++;
        }
    }

    if(wifi_interfaces.empty()){ throw manual_test_err("No WiFi interfaces found!"); }

    // Prompt user to select interface
    cout << "\nSelect an interface (enter number or name): ";
    string input;
    getline(cin, input);

    if(input.empty()){ throw manual_test_err("Selection cancelled."); }

    string selected_iface;
    try{
        // Try parsing as number
        int selection = stoi(input);
        if(selection < 1 || selection > static_cast<int>(wifi_interfaces.size())){
            throw manual_test_err("Invalid selection!");
        }
        selected_iface = wifi_interfaces[selection - 1];
    } catch(...){
        // Treat as interface name
        selected_iface = input;

        // Verify it exists in the list
        bool found = false;
        for(const auto &iface: wifi_interfaces){
            if(iface == selected_iface){
                found = true;
                break;
            }
        }
        if(!found){ throw manual_test_err("Interface '" + selected_iface + "' not found in available WiFi ifaces!"); }
    }

    cout << "Selected interface: " << selected_iface << "\n\n";
    return make_unique<string>(selected_iface);
}

void print_external_entities(const vector<ActorPtr> &entities){
    if(entities.empty()){
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

    for(const auto &entity: entities){
        if(entity->get_bool("AP")){
            aps.push_back(entity);
        } else{ stas.push_back(entity); }
    }

    Actor_config::print_ActorCMap("Access points", aps);
    Actor_config::print_ActorCMap("Stations:", stas);

    cout << "\n========================================\n";
    cout << "Total entities found: " << entities.size()
            << " (" << aps.size() << " APs, " << stas.size() << " STAs)\n";
    cout << "========================================\n\n";
}

bool ask_ok(const string &question){
    string input;
    do{
        cout << question << " (y/n): ";
        getline(cin, input);
        if(input == "ok" || input == "OK") return true;
        if(input == "y" || input == "Y") return true;
        if(input == "n" || input == "N") return false;
    } while(true);
}

ActorPtr wb_actor_selection(){
    cout << "\nThis test need OpenWrt devices defined in connection table" << endl;
    const path conn_table_path = absolute(path(PROJECT_ROOT_DIR) / "attack_config" /
        "example_whitebox_table.csv");

    cout << "Using connection table: " << conn_table_path << endl;
    vector<ActorPtr> actors = scan::get_actors_conn_table(conn_table_path);
    if(actors.empty()){ throw manual_test_err("ERROR: No actors found in connection table, test cant be run"); }
    cout << "\nFound " << actors.size() << " actor(s) in connection table:" << endl;

    for(size_t i = 0; i < actors.size(); ++i){
        const auto &actor = actors[i];
        cout << "  [" << i << "] ";
        if(actor->str_con["whitebox_host"].has_value()){
            cout << actor->str_con["whitebox_host"].value();
        } else{
            cout << "Actor_" << i;
        }
        cout << " " << actor->to_str() << endl;
        cout << endl;
    }

    // Select actor
    size_t selected_idx = 0;
    if(actors.size() > 1){
        cout << "\nSelect actor index [0-" << (actors.size() - 1) << "]: ";
        cin >> selected_idx;
        if(selected_idx >= actors.size()){ throw manual_test_err("ERROR: Invalid actor index"); }
    }
    return actors[selected_idx];
}

string get_openwrt_iface_wizard(const OpenWrtConn *conn){
    cli_section("OpenWrt Interface Selection for Tcpdump");

    const string output = conn->exec("ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://'");
    vector<string> ifaces;
    stringstream ss(output);
    string line;
    while(getline(ss, line)){
        ifaces.push_back(line);
    }

    if(ifaces.empty()){
        cout << "No interfaces found!" << endl;
        return "";
    }

    cout << "Available interfaces on OpenWrt:" << endl;
    for(size_t i = 0; i < ifaces.size(); ++i){
        cout << "  [" << i << "] " << ifaces[i] << endl;
    }

    cout << "\nSelect interface index [0-" << (ifaces.size() - 1) << "]: ";
    size_t idx;
    cin >> idx;
    if(idx >= ifaces.size()){
        cout << "Invalid index" << endl;
        return "";
    }
    return ifaces[idx];
}

int get_2_4_channel_wizard(){
    cli_section("WiFi Channel Selection");

    cout << "Available WiFi channels (2.4GHz):\n";
    cout << "  [1]  Channel 1  (2412 MHz)\n";
    cout << "  [2]  Channel 2  (2417 MHz)\n";
    cout << "  [3]  Channel 3  (2422 MHz)\n";
    cout << "  [4]  Channel 4  (2427 MHz)\n";
    cout << "  [5]  Channel 5  (2432 MHz)\n";
    cout << "  [6]  Channel 6  (2437 MHz)\n";
    cout << "  [7]  Channel 7  (2442 MHz)\n";
    cout << "  [8]  Channel 8  (2447 MHz)\n";
    cout << "  [9]  Channel 9  (2452 MHz)\n";
    cout << "  [10] Channel 10 (2457 MHz)\n";
    cout << "  [11] Channel 11 (2462 MHz)\n";
    cout << "  [12] Channel 12 (2467 MHz)\n";
    cout << "  [13] Channel 13 (2472 MHz)\n";
    cout << "  [14] Channel 14 (2484 MHz)\n";
    cout << "\nSelect channel [1-14]: ";

    int channel;
    cin >> channel;
    cin.ignore(); // Clear newline

    if(channel < 1 || channel > 14){
        throw manual_test_err("Invalid channel selection. Must be between 1-14.");
    }

    return channel;
}

TargetInfo get_target_wizard(const string &iface, int channel){
    cli_section("Target Selection - Scanning for Networks");

    cout << "Scanning for networks on channel " << channel << "...\n";
    cout << "Interface: " << iface << "\n\n";

    // Use list_external_entities function
    vector channels = {channel};
    RunStatus rs; // Create temporary RunStatus instance
    const vector<ActorPtr> entities = rs.list_external_entities(iface, 4, channels);

    vector<TargetInfo> targets;

    for(const auto &actor: entities){
        TargetInfo target;
        target.bssid = (*actor)["mac"];
        target.ssid = (*actor)["ssid"];
        target.channel = channel;

        // Skip if no SSID or MAC
        if(target.bssid.empty() || target.ssid.empty()){
            continue;
        }

        targets.push_back(target);
    }

    if(targets.empty()){ throw manual_test_err("No networks found on channel " + to_string(channel)); }

    // Sort by ssid
    ranges::sort(targets, [](const TargetInfo &a, const TargetInfo &b){ return a.ssid > b.ssid; });

    cout << "Found " << targets.size() << " networks:\n";
    cout << "  [IDX]  BSSID           SSID                    \n";
    cout << "  -----------------------------------------------\n";

    for(size_t i = 0; i < targets.size(); ++i){
        const auto &t = targets[i];
        cout << "  [" << setw(2) << i << "]  "
                << t.bssid << "  "
                << setw(16) << left << (t.ssid.length() > 16 ? t.ssid.substr(0, 13) + "..." : t.ssid) << "  "
                << setw(2) << t.channel << "\n";
    }

    cout << "\nSelect target [0-" << (targets.size() - 1) << "]: " << flush;
    size_t idx;
    cin >> idx;
    cin.ignore(); // Clear newline

    if(idx >= targets.size()){ throw manual_test_err("Invalid target selection."); }
    return targets[idx];
}
}
