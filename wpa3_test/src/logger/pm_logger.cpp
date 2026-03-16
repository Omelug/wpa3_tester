#include "logger/error_log.h"
#include "logger/log.h"
#include "system/ProcessManager.h"
#include <ranges>

namespace wpa3_tester{
    using namespace std;
    using namespace filesystem;
    using namespace chrono;

    // tshark like -t ad timestamp
    string ProcessManager::current_timestamp() {
        using clock = system_clock;
        const auto now = clock::now();
        const time_t t = clock::to_time_t(now);
        tm buf{};
        localtime_r(&t, &buf);

        // nanoseconds sub-second part
        const auto ns = duration_cast<nanoseconds>(now.time_since_epoch()) % 1'000'000'000;

        // timezone offset (+HHMM)
        char tz[8];
        strftime(tz, sizeof(tz), "%z", &buf);

        char datetime[32];
        strftime(datetime, sizeof(datetime), "%Y-%m-%dT%H:%M:%S", &buf);

        char out[64];
        snprintf(out, sizeof(out), "%s.%09lld%s", datetime, static_cast<long long>(ns.count()), tz);
        return out;
    }

    void ProcessManager::init_logging(const string &run_folder){
        std::lock_guard lock(mtx_);
        log_base_dir = path(run_folder) / "logger";
        recreate_log_folder(log_base_dir);

        // create combated log
        const path combined_path = log_base_dir / "combined.log";
        combined_log.close();
        combined_log.open(combined_path, ios::out | ios::trunc);
        if (!combined_log.is_open()) {
            log(LogLevel::ERROR, "Failed to open combined log file: "+ combined_path.string());
            throw runtime_error("Unable to open combined log file");
        }

        for (const auto &entry: processes | views::values) {
            if (entry->logs.log.is_open()) {entry->logs.log.close();}
            entry->logs.history.clear();
            entry->logs.history_enabled = false;
        }
    }

    void ProcessManager::write_log_line(ofstream &os, const string &line) {
        os << line << endl;
    }

    void ProcessManager::write_log_all(const string &line) {
        lock_guard lock(mtx_); //FIXME lock for spcific logs ?
        write_log_line(combined_log, line);
        for (const auto& [name, proc] : processes){
            const string prefix = current_timestamp() + " [" + name + "] [write_log_all] ";
            write_log_line(proc->logs.log, prefix + line);
        }
    }


    void ProcessManager::recreate_log_folder(const path &log_base_dir){
        error_code ec;

        // if log folder exists -> clear
        if (exists(log_base_dir, ec)) {
            remove_all(log_base_dir, ec);
            if (ec) {
                log(LogLevel::ERROR, "Failed to clean logger directory: "+log_base_dir.string()+":"+ec.message());
                throw runtime_error("Unable to clean logger directory");
            }
        }

        // create log folder
        create_directories(log_base_dir, ec);
        if (ec) {
            log(LogLevel::ERROR,"Failed to clean logger directory: "+log_base_dir.string()+":"+ec.message());
        }
    }

    // ----------------- history functions
    void ProcessManager::allow_history(const string &actor_name) {
        lock_guard lock(mtx_);
        if (const auto it = processes.find(actor_name); it != processes.end()) {
            it->second->logs.history_enabled = true;
            return;
        }
        throw setup_err("Process "+actor_name+" not found to allow history");
    }

    void ProcessManager::ignore_history(const string &actor_name) {
        if (const auto it = processes.find(actor_name); it != processes.end()) {
            it->second->logs.history_enabled = false;
            it->second->logs.history.clear();
            return;
        }
        throw setup_err("Process "+actor_name+" not found to ignore history");
    }

    void ProcessManager::discard_history(const string &actor_name) {
        lock_guard lock(mtx_);
        if (const auto it = processes.find(actor_name); it != processes.end()) {
            it->second->logs.history.clear();
            return;
        }
        throw setup_err("Process "+actor_name+" not found for discard history");
    }
    // -----------------------

}
