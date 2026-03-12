#include "ex_program/external_actors/ExternalConn.h"

#include "logger/error_log.h"

namespace wpa3_tester{
    using namespace std;

    ExternalConn::ExternalConn(Actor_config* actor){ // can be pointer here, if it will be from unique pointer
           this->actor = actor;
    };

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

        // auth with public key (preferred) or password
        if (ssh_userauth_publickey_auto(session, nullptr, nullptr) != SSH_AUTH_SUCCESS) {
            const string password = (*actor)["ssh_password"];
            if (ssh_userauth_password(session, nullptr, password.c_str()) != SSH_AUTH_SUCCESS) {
                const string error_msg = string("SSH authentication failed: ") + ssh_get_error(session);
                ssh_disconnect(session);
                ssh_free(session);
                session = nullptr;
                throw ex_conn_err(error_msg);
            }
        }
        return true;
    }

    string ExternalConn::get_hostname(){ return exec("uname -n"); }
    string ExternalConn::get_interfaces() { return exec("ip link show"); }
    string ExternalConn::get_wifi_status() { return exec("iwinfo"); }

    string ExternalConn::exec(const string& cmd) const{
        if (!session) {throw ex_conn_err("Cannot exec: not connected (call connect() first)");}

        const ssh_channel channel = ssh_channel_new(session);
        if (!channel) {throw ex_conn_err("Failed to create SSH channel");}

        // Helper lambda to clean up and throw
        auto cleanup_and_throw = [&](const string& msg) {
            ssh_channel_free(channel);
            throw ex_conn_err(msg);
        };

        if (ssh_channel_open_session(channel) != SSH_OK) {cleanup_and_throw("Failed to open SSH channel session");}
        if (ssh_channel_request_exec(channel, cmd.c_str()) != SSH_OK){
            cleanup_and_throw("Failed to execute command: " + cmd);
        }

        string result;
        char buf[1024];
        int n;
        while ((n = ssh_channel_read(channel, buf, sizeof(buf), 0)) > 0) {result.append(buf, n);}

        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return result;
    }

}
