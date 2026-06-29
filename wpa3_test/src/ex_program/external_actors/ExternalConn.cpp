#include "ex_program/external_actors/ExternalConn.h"
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <map>
#include <thread>
#include <libssh/sftp.h>
#include "config/Actor_Config/ActorPtr.h"
#include "config/global_config.h"
#include "logger/error_log.h"

#include <ranges>

namespace wpa3_tester{
using namespace std;
using namespace filesystem;

ExternalConn::ExternalConn() = default;

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
	const string &host = actor.get(SK::whitebox_ip);
	ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
	ssh_options_set(session, SSH_OPTIONS_USER, actor.get(SK::ssh_user).c_str());
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
	const string password = actor.get(SK::ssh_password);
	if(password.empty()){
		if(ssh_userauth_publickey_auto(session, nullptr, nullptr) != SSH_AUTH_SUCCESS) throw ex_conn_err(
			"SSH auth failed: no password and no key");
	} else{
		if(ssh_userauth_password(session, nullptr, password.c_str()) != SSH_AUTH_SUCCESS) throw ex_conn_err(
			"SSH auth failed: " + string(ssh_get_error(session)));
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

optional<string> ExternalConn::get_driver_hash(const string &driver_name) const{
	if(driver_name.empty()) return nullopt;
	// try srcversion first (fast path)
	string s = exec("cat /sys/module/" + driver_name + "/srcversion 2>/dev/null | tr -d '\\n'");
	if(!s.empty()) return s;
	// fallback: sha256 of the .ko file
	const string ko = exec("modinfo -F filename " + driver_name + " 2>/dev/null | tr -d '\\n\\r '");
	if(ko.empty() || ko == "(builtin)") return nullopt;
	string sha = exec("sha256sum " + ko + " 2>/dev/null | cut -c1-16 | tr -d '\\n'");
	while(!sha.empty() && (sha.back() == '\n' || sha.back() == '\r' || sha.back() == ' ')) sha.pop_back();
	if(sha.empty()) return nullopt;
	return sha;
}

optional<string> ExternalConn::get_module_hash(const string &driver_name) const{
	if(driver_name.empty()) return nullopt;
	// try srcversion for driver + depends; fallback per-module to sha256 of .ko
	const string cmd = "(for m in " + driver_name + " $(modinfo -F depends " + driver_name +
			" 2>/dev/null | grep -v '^modinfo:' | tr ',' ' '); do" " sv=$(cat /sys/module/$m/srcversion 2>/dev/null);"
			" if [ -z \"$sv\" ]; then" "   ko=$(modinfo -F filename $m 2>/dev/null);"
			"   [ -n \"$ko\" ] && sv=$(sha256sum $ko 2>/dev/null | cut -c1-16);" " fi;"
			" [ -n \"$sv\" ] && printf '%s:%s;' \"$m\" \"$sv\";" " done) | sha256sum | cut -c1-16";
	string s = exec(cmd);
	while(!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
	if(s.empty() || s == "-") return nullopt;
	return s;
}

string ExternalConn::exec(const string &cmd, const bool kill_on_exit, int *ret_err) const{
	lock_guard lock(session_mtx);
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
	if(ssh_channel_open_session(guard.ch) != SSH_OK) throw ex_conn_err(
		"Failed to open SSH channel: " + string(ssh_get_error(session)));
	if(ssh_channel_request_exec(guard.ch, final_cmd.c_str()) != SSH_OK) throw ex_conn_err(
		"Failed to execute: " + final_cmd + " | SSH error: " + ssh_get_error(session));

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
void ExternalConn::upload_file(const path &local_path, const path &remote_path) const{
	if(!session) throw ex_conn_err("SSH session not connected");

	ifstream local_f(local_path, ios::binary);
	if(!local_f) throw ex_conn_err("Local file not found: {}", local_path);

	const string contents{istreambuf_iterator<char>(local_f), istreambuf_iterator<char>()};

	ssh_scp scp = ssh_scp_new(session, SSH_SCP_WRITE, remote_path.parent_path().c_str());
	if(!scp) throw ex_conn_err("SCP init failed");
	if(ssh_scp_init(scp) != SSH_OK){
		ssh_scp_free(scp);
		throw ex_conn_err("SCP init failed: {}", ssh_get_error(session));
	}

	const string filename = remote_path.filename().string();
	if(ssh_scp_push_file(scp, filename.c_str(), contents.size(), 0644) != SSH_OK){
		ssh_scp_free(scp);
		throw ex_conn_err("SCP push file failed: {}", ssh_get_error(session));
	}

	if(ssh_scp_write(scp, contents.data(), contents.size()) != SSH_OK){
		ssh_scp_free(scp);
		throw ex_conn_err("SCP write failed: {}", ssh_get_error(session));
	}

	ssh_scp_close(scp);
	ssh_scp_free(scp);
}
#pragma GCC diagnostic pop

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
		throw ex_conn_err("SCP did not offer a new file (maybe path is wrong?): {}", remote_path);
	}

	size_t size = ssh_scp_request_get_size(scp);
	ofstream local_file(local_path, ios::binary);
	if(!local_file.is_open()){
		ssh_scp_deny_request(scp, "Cannot open local file");
		ssh_scp_free(scp);
		throw ex_conn_err("Error opening local file for writing: {}", local_path);
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

	log(LogLevel::DEBUG, "Successfully downloaded {} bytes via SCP to {}", size, local_path);
}
#pragma GCC diagnostic pop

void ExternalConn::on_disconnect(DisconnectCallback cb){
	disconnect_callbacks.push_back(std::move(cb));
}

void ExternalConn::disconnect(){
	if(!session) return;

	//LIFO
	for(auto &disconnect_callback: ranges::reverse_view(disconnect_callbacks)){
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

static const map<string, string> ARCH_TO_TRIPLE = {
	{"mips",    "mips-linux-musl"},
	{"mipsel",  "mipsel-linux-musl"},
	{"aarch64", "aarch64-linux-musl"},
	{"armv7l",  "arm-linux-musleabihf"},
	{"armv6l",  "arm-linux-musleabi"},
};

static path injector_source_path(){
	return read_symlink("/proc/self/exe").parent_path().parent_path().parent_path()
		   / "wpa3_test" / "remote_injector" / "main.c";
}

static void build_inject_binary(const string &arch, const path &out_path){
	const auto it = ARCH_TO_TRIPLE.find(arch);
	if(it == ARCH_TO_TRIPLE.end())
		throw ex_conn_err("No musl toolchain triple known for arch '{}'", arch);
	const string &triple = it->second;

	const path toolchain_dir = path(getenv("HOME")) / ".musl-cross" / (triple + "-cross");
	const path gcc = toolchain_dir / "bin" / (triple + "-gcc");

	if(!exists(gcc)){
		log(LogLevel::INFO, "Downloading musl toolchain for {} ({})...", arch, triple);
		const string url = "https://musl.cc/" + triple + "-cross.tgz";
		create_directories(toolchain_dir.parent_path());
		const string dl_cmd = "curl -fsSL '" + url + "' | tar xz -C '" + toolchain_dir.parent_path().string() + "'";
		if(system(dl_cmd.c_str()) != 0)
			throw ex_conn_err("Failed to download musl toolchain from {}", url);
	}

	log(LogLevel::INFO, "Cross-compiling remote_injector for {}...", arch);
	const string cc_cmd = "'" + gcc.string() + "' -O2 -static -no-pie -o '" + out_path.string()
						  + "' '" + injector_source_path().string() + "'";
	if(system(cc_cmd.c_str()) != 0)
		throw ex_conn_err("Cross-compilation failed for arch {}", arch);
	log(LogLevel::INFO, "Built {}", out_path);
}

static path injector_local_path(const string &remote_arch){
	const path bin_dir = read_symlink("/proc/self/exe").parent_path();
	const path arch_binary = bin_dir / ("remote_injector_" + remote_arch);
	if(exists(arch_binary)) return arch_binary;

	if(!get_global_run_config().get_install_req()) //FIXME global (but it makes ssence here)
		throw ex_conn_err("No remote_injector binary for arch '{}' — place it at {} "
						  "or set install_req: true to build automatically", remote_arch, arch_binary);

	build_inject_binary(remote_arch, arch_binary);
	return arch_binary;
}

ssh_channel ExternalConn::open_capture_channel(const string &iface) const{
	lock_guard lock(session_mtx);
	const ssh_channel ch = ssh_channel_new(session);
	if(!ch) throw ex_conn_err("open_capture_channel: ssh_channel_new failed");
	if(ssh_channel_open_session(ch) != SSH_OK){
		ssh_channel_free(ch);
		throw ex_conn_err("open_capture_channel: open_session failed");
	}
	const string cmd = "tcpdump -i " + iface + " -U -w - 2>/dev/null";
	if(ssh_channel_request_exec(ch, cmd.c_str()) != SSH_OK){
		ssh_channel_send_eof(ch);
		ssh_channel_close(ch);
		ssh_channel_free(ch);
		throw ex_conn_err("open_capture_channel: exec failed on " + iface);
	}
	return ch;
}

void ExternalConn::ensure_inject_binary() const{
	constexpr string_view remote_path = "/tmp/wpa3_injector";
	string arch = exec("uname -m 2>/dev/null");
	while(!arch.empty() && (arch.back() == '\n' || arch.back() == '\r')) arch.pop_back();

	// uname -m returns "mips" on both BE and LE MIPS Linux; use opkg arch to detect endianness
	if(arch == "mips"){
		const string opkg_arch = exec("opkg print-architecture 2>/dev/null | awk '/mips/{print $2; exit}'", false);
		if(opkg_arch.find("mipsel") != string::npos)
			arch = "mipsel";
	}

	const path local_binary = injector_local_path(arch);

	int ret = 0;
	const string remote_size = exec(string("stat -c%s ") + string(remote_path) + " 2>/dev/null", false, &ret);
	const auto local_size = to_string(file_size(local_binary));
	if(ret != 0 || remote_size.substr(0, remote_size.find('\n')) != local_size){
		log(LogLevel::INFO, "Uploading remote_injector ({}) -> {}", arch, remote_path);
		upload_file(local_binary, remote_path);
		exec(string("chmod +x ") + string(remote_path));
	}
}

ssh_channel ExternalConn::open_inject_channel(const string &iface) const{
	ensure_inject_binary();
	constexpr string_view remote_path = "/tmp/wpa3_injector";
	lock_guard lock(session_mtx);
	const ssh_channel ch = ssh_channel_new(session);
	if(!ch) throw ex_conn_err("open_inject_channel: ssh_channel_new failed");
	if(ssh_channel_open_session(ch) != SSH_OK){
		ssh_channel_free(ch);
		throw ex_conn_err("open_inject_channel: open_session failed");
	}
	const string cmd = string(remote_path) + " " + iface;
	if(ssh_channel_request_exec(ch, cmd.c_str()) != SSH_OK){
		ssh_channel_send_eof(ch);
		ssh_channel_close(ch);
		ssh_channel_free(ch);
		throw ex_conn_err("open_inject_channel: exec failed on " + iface);
	}
	// Give the process ~50 ms to start; if it exits immediately, read stderr for diagnosis.
	this_thread::sleep_for(chrono::milliseconds(50));
	if(ssh_channel_is_eof(ch)){
		char errbuf[512] = {};
		ssh_channel_read_nonblocking(ch, errbuf, sizeof(errbuf) - 1, 1 /* stderr */);
		ssh_channel_send_eof(ch);
		ssh_channel_close(ch);
		ssh_channel_free(ch);
		throw ex_conn_err("remote_injector exited immediately on {}: {}", iface, errbuf[0] ? errbuf : "(no stderr)");
	}
	log(LogLevel::INFO, "remote_injector running on {}", iface);
	return ch;
}
}