#pragma once
#include <iostream>
#include <ostream>
#include <tins/tins.h>
#include "config/RunStatus.h"

using Tins::HWAddress;
using Tins::NetworkInterface;
using Tins::Dot11Beacon;
using Tins::RadioTap;
using Tins::Dot11ManagementFrame;
using Tins::PacketSender;
using std::string;
using std::cout;
using std::endl;

extern volatile bool g_stop;

void send_CSA_beacon(const HWAddress<6>& ap_mac,
                     const HWAddress<6>& sta_mac,
                     const NetworkInterface& iface,
                     const string& ssid,
                     int ap_channel);

void check_vulnerable(const HWAddress<6>& ap_mac,
                      const HWAddress<6>& sta_mac,
                      const string iface_name,
                      const string& ssid,
                      int ap_channel);

void setup_chs_attack(RunStatus& rs);
void run_chs_attack(RunStatus& rs);
