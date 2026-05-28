#include "ex_program/external_actors/ExternalConn.h"
#include "logger/error_log.h"
#include <libssh/sftp.h>
#include <fcntl.h>

#include <ranges>

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

ExternalConn::ExternalConn()= default;

ExternalConn::~ExternalConn(){
	if(session){
		// clean up all process associated with this session
		try{ ExternalConn::exec("pkill -s 0 -TERM"); } catch(...){}
		ssh_disconnect(session);
		ssh_free(session);
	}
}

bool ExternalConn::connect(const ActorPtr &actor){
	// Check if actor has needed SSH params
	if(!actor[SK::whitebox_ip].has_value() || !actor[SK::ssh_user].has_value() || !actor[SK::ssh_password].has_value()){
		throw ex_conn_err("ExternalConn: actor missing whitebox_ip");
	}

	// new ssh session
	session = ssh_new();
	if(!session){ throw ex_conn_err("ssh_new failed"); }

	// ssh options
	const string &host = actor["whitebox_ip"];
	ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
	ssh_options_set(session, SSH_OPTIONS_USER, actor["ssh_user"].c_str());
	const int port = stoi(actor->get_or(SK::ssh_port, "22"));
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);

	// connect to host
	if(ssh_connect(session) != SSH_OK){
		const string error_msg = string("SSH connection failed to ") + host + ": " + ssh_get_error(session);
		ssh_free(session);
		session = nullptr;
		throw ex_conn_err(error_msg);
	}

	// auth with password (preferred) or public key
	const string password = actor["ssh_password"];
	if(password.empty()){
		if(ssh_userauth_publickey_auto(session, nullptr, nullptr) != SSH_AUTH_SUCCESS)
			throw ex_conn_err("SSH auth failed: no password and no key");
	} else{
		if(ssh_userauth_password(session, nullptr, password.c_str()) != SSH_AUTH_SUCCESS)
			throw ex_conn_err("SSH auth failed: " + string(ssh_get_error(session)));
	}
	return true;
}

string ExternalConn::get_hostname(){ return exec("uname -n"); }

vector<string> ExternalConn::get_radio_list(){
	throw not_implemented_err("not default get_interface function");
}

string ExternalConn::get_mac_address(const string &iface) const{
	return exec("cat /sys/class/net/" + iface + "/address 2>/dev/null | tr -d '\\n'");
}

string ExternalConn::get_driver(const string &radio) const{
	// radio0 → phy0 → /sys/class/ieee80211/phy0/device/driver
	const string phy = "phy" + radio.substr(5); // "radio0" → "phy0"
	return exec("basename $(readlink /sys/class/ieee80211/" + phy + "/device/driver) 2>/dev/null | tr -d '\\n'");
}

string ExternalConn::exec(const string &cmd, const bool kill_on_exit, int *ret_err) const{
	std::lock_guard lock(session_mtx);
	const string final_cmd = kill_on_exit ? string("setsid sh -c 'trap \"kill -- -$$\" EXIT; ") + cmd + "'" : cmd;
	//log(LogLevel::DEBUG, "exec "+final_cmd);
	if(!session) throw ex_conn_err("Cannot exec: not connected");

	const struct ChannelGuard{
		ssh_channel ch;
		explicit ChannelGuard(const ssh_session s): ch(ssh_channel_new(s)){}

		~ChannelGuard(){
			if(ch){
				ssh_channel_send_eof(ch);
				ssh_channel_close(ch);
				ssh_channel_free(ch);
			}
		}
	} guard(session);

	if(!guard.ch) throw ex_conn_err("Failed to create SSH channel: " + string(ssh_get_error(session)));
	if(ssh_channel_open_session(guard.ch) != SSH_OK)
		throw ex_conn_err("Failed to open SSH channel: " + string(ssh_get_error(session)));
	if(ssh_channel_request_exec(guard.ch, final_cmd.c_str()) != SSH_OK)
		throw ex_conn_err("Failed to execute: " + final_cmd + " | SSH error: " + ssh_get_error(session));

	string result;
	char buf[1024];
	int n;
	while((n = ssh_channel_read(guard.ch, buf, sizeof(buf), 0)) > 0){ result.append(buf, n); }

	if(ret_err){
		#  pragma GCC diagnostic push
		#  pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		*ret_err = ssh_channel_get_exit_status(guard.ch);
		#  pragma GCC diagnostic pop
	}
	return result;
}

void ExternalConn::create_sniff_iface(const string &iface, const string &sniff_iface) const{
	exec("iw dev " + sniff_iface + " del 2>/dev/null");
	//FIXME quiet fallback, check before if possible
	const string add_cmd = "iw dev " + iface + " interface add " + sniff_iface + " type monitor flags fcsfail otherbss"
			+ " || iw dev " + iface + " interface add " + sniff_iface + " type monitor";
	exec("ip link show " + sniff_iface + " >/dev/null 2>&1 && ip link delete " + sniff_iface);

	exec(add_cmd);
	exec("ip link set " + sniff_iface + " up");
}

bool ExternalConn::set_channel(const string &iface, const Channel &ch) const{
	int ret = 0;
	string cmd = "iw dev " + iface + " set channel " + to_string(ch.ch_num);
	if(ch.ht_mode.has_value()){ cmd += " " + ch.ht_mode.value(); }
	cmd += " 2>&1";
	exec(cmd, false, &ret);
	return ret;
}

void ExternalConn::set_monitor_mode(const string &iface) const{
	exec("ip link set " + iface + " down");
	exec("iw dev " + iface + " set type monitor");
	exec("ip link set " + iface + " up");
}

void ExternalConn::set_managed_mode(const string &iface) const{
	exec("ip link set " + iface + " down");
	exec("iw dev " + iface + " set type managed");
	exec("ip link set " + iface + " up");
}

void ExternalConn::set_ip(const string &iface, const string &ip_addr) const{
	exec("ip addr flush dev " + iface);
	exec("ip addr add " + ip_addr + "/24 dev " + iface);
	exec("ip link set " + iface + " up");
}

void ExternalConn::upload_file(const path &local_path, const path &remote_path) const{
	if(!session) throw ex_conn_err("SSH session not connected");

	const sftp_session sftp = sftp_new(session);
	if(!sftp || sftp_init(sftp) != SSH_OK){
		if(sftp) sftp_free(sftp);
		throw ex_conn_err("SFTP init failed");
	}

	ifstream local_f(local_path, ios::binary);
	if(!local_f){
		sftp_free(sftp);
		throw ex_conn_err("Local file not found: " + local_path.string());
	}

	const sftp_file remote_f = sftp_open(sftp, remote_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if(!remote_f){
		sftp_free(sftp);
		throw ex_conn_err("Remote open failed");
	}

	char buffer[4096];
	while(local_f.read(buffer, sizeof(buffer)) || local_f.gcount() > 0){
		if(sftp_write(remote_f, buffer, local_f.gcount()) < 0) break;
	}

	sftp_close(remote_f);
	sftp_free(sftp);
}

void ExternalConn::upload_script_raw(const path &local_path, const path &remote_path) const{
	ifstream ifile(local_path);
	if(!ifile) throw ex_conn_err("Local script not found");

	stringstream buffer;
	buffer << ifile.rdbuf();
	string content = buffer.str();
	// works for text files, no for binary data (null bytes etc.)
	exec("cat << 'EOF' > " + remote_path.string() + "\n" + content + "\nEOF\n");
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
void ExternalConn::download_file(const path &remote_path, const path &local_path) const{
	if(!session) throw ex_conn_err("SSH session not connected");

	ssh_scp scp = ssh_scp_new(session, SSH_SCP_READ, remote_path.c_str());
	if(scp == nullptr){
		throw ex_conn_err("Error allocating SCP session: " + string(ssh_get_error(session)));
	}

	if(ssh_scp_init(scp) != SSH_OK){
		string err = ssh_get_error(session);
		ssh_scp_free(scp);
		throw ex_conn_err("Error initializing SCP session: " + err);
	}

	if(int res = ssh_scp_pull_request(scp); res != SSH_SCP_REQUEST_NEWFILE){
		ssh_scp_free(scp);
		throw ex_conn_err("SCP did not offer a new file (maybe path is wrong?): " + remote_path.string());
	}

	size_t size = ssh_scp_request_get_size(scp);
	ofstream local_file(local_path, ios::binary);
	if(!local_file.is_open()){
		ssh_scp_deny_request(scp, "Cannot open local file");
		ssh_scp_free(scp);
		throw ex_conn_err("Error opening local file for writing: " + local_path.string());
	}

	ssh_scp_accept_request(scp);

	char buffer[4096];
	size_t downloaded = 0;
	while(downloaded < size){
		int to_read = static_cast<int>((size - downloaded > sizeof(buffer)) ? sizeof(buffer) : (size - downloaded));
		int nbytes = ssh_scp_read(scp, buffer, to_read);

		if(nbytes == SSH_ERROR){
			string err = ssh_get_error(session);
			ssh_scp_free(scp);
			local_file.close();
			throw ex_conn_err("Error reading from SCP: " + err);
		}

		local_file.write(buffer, nbytes);
		downloaded += nbytes;
	}

	ssh_scp_close(scp);
	ssh_scp_free(scp);
	local_file.close();

	log(LogLevel::DEBUG, "Successfully downloaded {} bytes via SCP to {}", size, local_path.string());
}
#pragma GCC diagnostic pop

void ExternalConn::on_disconnect(DisconnectCallback cb){
	disconnect_callbacks.push_back(std::move(cb));
}

void ExternalConn::disconnect(){
	if(!session) return;

	//LIFO
	for(auto & disconnect_callback : ranges::reverse_view(disconnect_callbacks)){
		try{
			if(disconnect_callback) disconnect_callback();
		} catch(const exception &e){
			log(LogLevel::ERROR, "Error in disconnect callback: {}", e.what());
		}
	}

	disconnect_callbacks.clear();

	ssh_disconnect(session);
	ssh_free(session);
	session = nullptr;
}
}