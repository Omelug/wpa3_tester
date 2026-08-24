#pragma once
#include <filesystem>

using namespace std;
using namespace filesystem;

namespace wpa3_tester{

path get_usb_auth_path(const std::string& iface_name);
void disconnect_usb_device(const std::string& iface_name);
void connect_usb_device(const std::string& iface_name);
void connect_usb_device(const path& auth_file);
void reset_usb_ifaces();

}
