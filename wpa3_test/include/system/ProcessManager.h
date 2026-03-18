#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <regex>
#include <functional>
#include <reproc++/reproc.hpp>

namespace wpa3_tester{
    class ProcessManager{
        mutable std::mutex mtx_; // for processes and process_logs security

    public:

        // log for whole test
        std::filesystem::path log_base_dir;
        std::ofstream combined_log;

        //TODO lépe popsat mutexy, je v tom strašnej zmatek
        struct WaitListener {
            std::regex pattern{};
            bool active = false;
            bool matched = false;
        };

        struct ProcessLogs {
            std::ofstream log;
            std::string   history;
            bool          history_enabled = false;
            WaitListener  wait;
        };

        struct ManagedProcess {
            std::shared_ptr<reproc::process> proc;
            std::thread drain_thread;
            std::atomic<bool> shutting_down{false};
            ProcessLogs logs;
            std::function<void()> on_stop_callback;
        };

        std::map<std::string,std::shared_ptr<ManagedProcess>> processes;
        std::mutex wait_mutex;
        std::condition_variable wait_cv;

        static void write_log_line(std::ofstream &os, const std::string &line);
        void write_log_all(const std::string &line);

    private:
        static void recreate_log_folder(const std::filesystem::path &log_base_dir);
        void handle_chunk(const std::shared_ptr<ManagedProcess> &mp, const std::string &process_name,
                          const std::string &label,
                          const std::string &data);
        void start_drain_for(const std::string &process_name, const std::shared_ptr<ManagedProcess>& mp);
    public:
        ProcessManager() = default;
        ~ProcessManager();

        ProcessManager(const ProcessManager&) = delete;
        ProcessManager& operator=(const ProcessManager&) = delete;

        static std::string current_timestamp();
        void init_logging(const std::string& run_folder);

        // what can actors
        void run(const std::string& process_name,
                 const std::vector<std::string> &cmd,
                 const std::filesystem::path &working_dir = {});

        void allow_history(const std::string &actor_name);
        void ignore_history(const std::string &actor_name);
        void discard_history(const std::string &actor_name);

        void wait_for(const std::string &actor_name, const std::string &pattern,
                      std::chrono::seconds timeout = std::chrono::minutes(60)); // 60 minutes (practically infinity)
        void stop(const std::string &process_name);
        void on_stop(const std::string& process_name, const std::function<void()> &callback);

        void stop_all();
    };
}