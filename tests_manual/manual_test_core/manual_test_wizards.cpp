#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

#include "config/RunStatus.h"
#include "system/hw_capabilities.h"
#include "manual_test_wizards.h"

namespace wpa3_tester::manual_tests {
    using namespace std;
    void cli_section(const string& section_title){
        cout << "\n========================================\n";
        cout << "  " << section_title <<" \n";
        cout << "========================================\n\n";
    }

    string get_iface_wizard() {
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
        for (const auto& [iface_name, iface_type] : interfaces) {
            if (iface_type == InterfaceType::Wifi ||
                iface_type == InterfaceType::WifiVirtualMon) {
                cout << left << setw(5) << index
                     << setw(20) << iface_name
                     << setw(20) << iface_to_string(iface_type) << "\n";
                wifi_interfaces.push_back(iface_name);
                index++;
            }
        }

        if (wifi_interfaces.empty()) {
            cout << "\nNo WiFi interfaces found!\n";
            cout << "Please ensure you have WiFi hardware available.\n";
            return "";
        }

        // Prompt user to select interface
        cout << "\nSelect an interface (enter number or name): ";
        string input;
        getline(cin, input);

        if (input.empty()) {
            cout << "Selection cancelled.\n";
            return "";
        }

        string selected_iface;
        try {
            // Try parsing as number
            int selection = stoi(input);
            if (selection < 1 || selection > static_cast<int>(wifi_interfaces.size())) {
                cout << "Invalid selection!\n";
                return "";
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
            if (!found) {
                cout << "Interface '" << selected_iface << "' not found in available WiFi interfaces!\n";
                return "";
            }
        }

        cout << "Selected interface: " << selected_iface << "\n\n";
        return selected_iface;
    }

    /**
     * Helper function to print external entities in a formatted table
     */
    void print_external_entities(const vector<ExternalEntity>& entities) {
        if (entities.empty()) {
            cout << "No entities found!\n";
            cout << "\nPossible reasons:\n";
            cout << "  - No WiFi activity in range\n";
            cout << "  - Interface not in proper mode\n";
            cout << "  - Scan duration too short\n";
            return;
        }

        // Separate APs and STAs
        vector<ExternalEntity> aps;
        vector<ExternalEntity> stas;

        for (const auto& entity : entities) {
            if (entity.is_ap) { aps.push_back(entity);
            } else { stas.push_back(entity);}
        }

        // Display Access Points
        cout << "\nAccess Points (" << aps.size() << " found):\n";
        cout << string(80, '-') << "\n";
        cout << left << setw(20) << "MAC Address"
             << setw(25) << "SSID"
             << setw(10) << "Channel"
             << setw(10) << "Signal" << "\n";
        cout << string(80, '-') << "\n";

        for (const auto& ap : aps) {
            cout << left << setw(20) << ap.mac
                 << setw(25) << (ap.ssid.empty() ? "<hidden>" : ap.ssid)
                 << setw(10);
            if (ap.channel == 0) { cout << "N/A";
            } else { cout << ap.channel;}
            cout << setw(10);
            if (ap.signal == 0) { cout << "N/A";
            } else { cout << ap.signal << " dBm";}
            cout << "\n";
        }

        cout << "\n";

        // Display Stations
        cout << "Stations (" << stas.size() << " found):\n";
        cout << string(80, '-') << "\n";
        cout << left << setw(20) << "MAC Address"
             << setw(25) << "SSID (if known)"
             << setw(10) << "Signal" << "\n";
        cout << string(80, '-') << "\n";

        for (const auto& sta : stas) {
            cout << left << setw(20) << sta.mac
                 << setw(25) << (sta.ssid.empty() ? "N/A" : sta.ssid)
                 << setw(10);
            if (sta.signal == 0) { cout << "N/A";
            } else {cout << sta.signal << " dBm";}
            cout << "\n";
        }

        cout << "\n========================================\n";
        cout << "Total entities found: " << entities.size()
             << " (" << aps.size() << " APs, " << stas.size() << " STAs)\n";
        cout << "========================================\n\n";
    }
}
