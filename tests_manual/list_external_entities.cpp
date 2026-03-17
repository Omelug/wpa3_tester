#include <iostream>
#include <string>
#include "config/RunStatus.h"
#include "manual_test_core/manual_test_wizards.h"


using namespace std;
using namespace wpa3_tester;

// TODO  popsat a upravit,
int main() {
    manual_tests::cli_section("External Entity Scanner - Manual Test");

    const string selected_iface = manual_tests::get_iface_wizard();
    if (selected_iface.empty()) {cout << "No interface selected. Exiting.\n"; return 1;}

    //timeout ?
    cout << "Enter scan timeout in seconds (default: 30): ";
    string timeout_input;
    getline(cin, timeout_input);

    int timeout = 30;
    if (!timeout_input.empty()) {
        try {
            timeout = stoi(timeout_input);
            if (timeout < 1 || timeout > 300) {
                cout << "Timeout must be between 1 and 300 seconds. Using default (30).\n";
                timeout = 30;
            }
        } catch (...) {
            cout << "Invalid timeout value. Using default (30).\n";
            timeout = 30;
        }
    }

    const Actor_config actor{};
    actor["iface"] = selected_iface;
    actor.set_monitor_mode();
    cout << "\nScanning on interface '" << selected_iface << "' for " << timeout << " seconds...\n";
    cout << "Please wait...\n";

    vector<ActorPtr> entities;
    try {
        entities = RunStatus::list_external_entities(selected_iface, timeout);
    } catch (const exception& e) {
        cout << "Error during scanning: " << e.what() << "\n";
        cout << "\nPossible issues:\n";
        cout << "  - Interface may not be in monitor mode\n";
        cout << "  - You may need root privileges\n";
        cout << "  - Interface may be busy\n";
        return 1;
    }

    manual_tests::cli_section("Scan Results");
    manual_tests::print_external_entities(entities);

    return 0;
}

