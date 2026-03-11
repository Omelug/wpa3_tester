#include "ex_program/openwrt/OpenWrtConn.h"
#include <stdexcept>

namespace wpa3_tester {
    OpenWrtConn::OpenWrtConn(const std::string& host, const std::string& user, int port) {
        session = ssh_new();
        if (!session) throw std::runtime_error("ssh_new failed");

        ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
        ssh_options_set(session, SSH_OPTIONS_USER, user.c_str());
        ssh_options_set(session, SSH_OPTIONS_PORT, &port);

        if (ssh_connect(session) != SSH_OK)
            throw std::runtime_error("Connection failed: " + std::string(ssh_get_error(session)));

        // authenticate with key (preferred) or password
        if (ssh_userauth_publickey_auto(session, nullptr, nullptr) != SSH_AUTH_SUCCESS)
            throw std::runtime_error("Auth failed: " + std::string(ssh_get_error(session)));
    }

    OpenWrtConn::~OpenWrtConn() {
        if (session) {
            ssh_disconnect(session);
            ssh_free(session);
        }
    }

    std::string OpenWrtConn::exec(const std::string& cmd) {
        ssh_channel channel = ssh_channel_new(session);
        if (!channel) throw std::runtime_error("channel_new failed");

        if (ssh_channel_open_session(channel) != SSH_OK) {
            ssh_channel_free(channel);
            throw std::runtime_error("channel_open failed");
        }

        if (ssh_channel_request_exec(channel, cmd.c_str()) != SSH_OK) {
            ssh_channel_free(channel);
            throw std::runtime_error("exec failed: " + cmd);
        }

        std::string result;
        char buf[1024];
        int n;
        while ((n = ssh_channel_read(channel, buf, sizeof(buf), 0)) > 0)
            result.append(buf, n);

        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return result;
    }

    // UCI helpers
    std::string OpenWrtConn::uci_get(const std::string& path) {
        return exec("uci get " + path);
    }

    void OpenWrtConn::uci_set(const std::string& path, const std::string& value) {
        exec("uci set " + path + "='" + value + "'");
        exec("uci commit");
    }
}
