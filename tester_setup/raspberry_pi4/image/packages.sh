#!/usr/bin/env bash
WPA3_APT_PACKAGES=(
    build-essential cmake ninja-build ccache
    clang lld mold pkg-config flex bison git g++-14
    libssl-dev
    libnl-3-dev libnl-genl-3-dev libnl-route-3-dev
    libpcap-dev
    libssh-dev
    libyaml-cpp-dev
    libtins-dev
    iproute2 iw tcpdump iptables socat dnsmasq fish
    libgeoip-dev liburcu-dev libcli-dev libsodium-dev libnet1-dev
    libcurl4-openssl-dev
    usb-modeswitch usb-modeswitch-data uhubctl
    avahi-daemon quilt trace-cmd gdbserver bc
    tshark iperf3 gnuplot
    hcxtools
    netsniff-ng
    dkms linux-headers-rpi-v8
    sshpass
    python3-pip
)
