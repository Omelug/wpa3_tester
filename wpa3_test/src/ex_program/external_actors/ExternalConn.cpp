#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"
#include <sstream>

namespace wpa3_tester{
    using namespace std;

    ExternalConn::ExternalConn(const ActorPtr &actor): actor(actor){};

    ExternalConn::~ExternalConn(){
        if (session) {
            ssh_disconnect(session);
            ssh_free(session);
        }
    }

    bool ExternalConn::connect(){

        // Check if actor has needed SSH params
        if (!actor->str_con["whitebox_ip"].has_value()  ||
            !actor->str_con["ssh_user"].has_value()     ||
            !actor->str_con["ssh_password"].has_value()) {
            throw ex_conn_err("ExternalConn: actor missing whitebox_ip");
        }

        // new ssh session
        session = ssh_new();
        if (!session) {throw ex_conn_err("ssh_new failed");}

        // ssh options
        const string& host = (*actor)["whitebox_ip"];
        ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
        ssh_options_set(session, SSH_OPTIONS_USER, (*actor)["ssh_user"].c_str());
        const int port = stoi(actor->str_con["ssh_port"].value_or("22"));
        ssh_options_set(session, SSH_OPTIONS_PORT, &port);

        // connect to host
        if (ssh_connect(session) != SSH_OK) {
            const string error_msg = string("SSH connection failed to ") + host + ": " + ssh_get_error(session);
            ssh_free(session);
            session = nullptr;
            throw ex_conn_err(error_msg);
        }

        // auth with password (preferred) or public key
        const string password = (*actor)["ssh_password"];
        if (password.empty()) {
            if (ssh_userauth_publickey_auto(session, nullptr, nullptr) != SSH_AUTH_SUCCESS)
                throw ex_conn_err("SSH auth failed: no password and no key");
        } else {
            if (ssh_userauth_password(session, nullptr, password.c_str()) != SSH_AUTH_SUCCESS)
                throw ex_conn_err("SSH auth failed: " + string(ssh_get_error(session)));
        }
        return true;
    }

    string ExternalConn::get_hostname(){ return exec("uname -n"); }

    vector<string> ExternalConn::get_interfaces() {
        // list only wifi (802.11) interfaces via iw
        const string output = exec("iw dev 2>/dev/null | awk '/Interface/{print $2}'");
        vector<string> ifaces;
        istringstream ss(output);
        string line;
        while (getline(ss, line)) { //TODo getline cykly pak pojít a pokud jde, zjednodušit
            const auto start = line.find_first_not_of(" \t\r\n");
            if (start == string::npos) continue;
            line = line.substr(start, line.find_last_not_of(" \t\r\n") - start + 1);
            if (!line.empty()) ifaces.push_back(line);
        }
        return ifaces;
    }

    string ExternalConn::get_wifi_status() { return exec("iwinfo"); }

    string ExternalConn::exec(const string& cmd, int* ret_code) const {
        if (!session) throw ex_conn_err("Cannot exec: not connected");

        const struct ChannelGuard {
            ssh_channel ch;
            explicit ChannelGuard(ssh_session s) : ch(ssh_channel_new(s)) {}
            ~ChannelGuard() { if (ch) { ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch); } }
        } guard(session);

        if (!guard.ch) throw ex_conn_err("Failed to create SSH channel");
        if (ssh_channel_open_session(guard.ch) != SSH_OK)
            throw ex_conn_err("Failed to open SSH channel");
        if (ssh_channel_request_exec(guard.ch, cmd.c_str()) != SSH_OK)
            throw ex_conn_err("Failed to execute: " + cmd);

        string result;
        char buf[1024];
        int n;
        while ((n = ssh_channel_read(guard.ch, buf, sizeof(buf), 0)) > 0)
            result.append(buf, n);

        if (ret_code) {
            uint32_t exit_status = 0;
            ssh_channel_get_exit_state(guard.ch, &exit_status, nullptr, nullptr);
            *ret_code = static_cast<int>(exit_status);
        }
        return result;
    }

    void ExternalConn::create_sniff_iface(const std::string &iface, const std::string &sniff_iface) const{
        //FIXME quiet fallback, check before if possible
        const string add_cmd = "iw dev " + iface + " interface add " + sniff_iface + " type monitor flags fcsfail otherbss"
                             + " || iw dev " + iface + " interface add " + sniff_iface + " type monitor";
        exec(add_cmd);
        exec("ip link set " + sniff_iface + " up");
    }

    bool ExternalConn::set_channel(const std::string &iface, const int channel) const{
        int ret; // for monitor/station mód
        exec("iw dev " + iface + " set channel " + to_string(channel) + " 2>&1", &ret);
        return ret;
    }

    void ExternalConn::set_monitor_mode(const std::string &iface) const{
        exec("ip link set " + iface + " down");
        exec("iw dev " + iface + " set type monitor");
        exec("ip link set " + iface + " up");
    }

    void ExternalConn::set_managed_mode(const std::string &iface) const{
        exec("ip link set " + iface + " down");
        exec("iw dev " + iface + " set type managed");
        exec("ip link set " + iface + " up");
    }

    string ExternalConn::get_mac_address(const string &iface) const{
        return exec("cat /sys/class/net/" + iface + "/address 2>/dev/null | tr -d '\\n'");
    }

    std::string ExternalConn::get_driver(const std::string &iface) const{
        return exec("basename $(readlink /sys/class/net/" + iface + "/device/driver) 2>/dev/null | tr -d '\\n'");
    }
}
