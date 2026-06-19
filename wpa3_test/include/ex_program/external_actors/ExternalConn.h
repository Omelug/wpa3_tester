#pragma once
#include <optional>
#include <libssh/libssh.h>
#include "logger/error_log.h"
#include "system/wifi_channel.h"

namespace wpa3_tester{
class RunStatus;
class Actor_config;

class ExternalConn{
public:
	using DisconnectCallback = std::function<void()>;
protected:
	mutable std::mutex session_mtx; //mutex to create ssh channels
	std::vector<DisconnectCallback> disconnect_callbacks;
	ssh_session session = nullptr;
public:
	explicit ExternalConn();
	virtual ~ExternalConn();
	virtual bool connect(const ActorPtr &actor);

	virtual std::string get_hostname();
	virtual std::vector<std::string> get_radio_list();
	std::string get_mac_address(const std::string &iface) const;
	std::string get_driver(const std::string &radio) const;
	std::optional<std::string> get_driver_hash(const std::string &driver_name) const;
	std::optional<std::string> get_module_hash(const std::string &driver_name) const;

	virtual std::string exec(const std::string &cmd, bool kill_on_exit = false, int *ret_err = nullptr) const;
	void create_sniff_iface(const std::string &iface, const std::string &sniff_iface) const;
	bool set_channel(const std::string &iface, const Channel &ch) const;
	virtual void set_monitor_mode(const std::string &iface) const;
	virtual void set_managed_mode(const std::string &iface) const;
	virtual void set_ip(const std::string &iface, const std::string &ip_addr) const;
	void upload_file(const std::filesystem::path &local_path, const std::filesystem::path &remote_path) const;
	void upload_script_raw(const std::filesystem::path &local_path, const std::filesystem::path &remote_path) const;
	void download_file(const std::filesystem::path &remote_path, const std::filesystem::path &local_path) const;

	virtual void setup_ap(const RunStatus &, ActorPtr &){
		throw not_implemented_err("setup_ap");
	}

	virtual void setup_iface(const std::string &, ActorPtr &, nlohmann::json){
		throw not_implemented_err("setup_iface");
	}

	virtual void check_req(const nlohmann::json &, const std::string &){
		throw not_implemented_err("check_req");
	}

	virtual void logger(RunStatus &, const std::string &){
		throw not_implemented_err("logger");
	}

	virtual void get_hw_capabilities(ActorPtr &, const std::string &){
		throw not_implemented_err("get_hw_capabilities");
	}

	void on_disconnect(DisconnectCallback cb);
	void disconnect();
};
}