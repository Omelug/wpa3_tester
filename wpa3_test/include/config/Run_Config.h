#pragma once
#include <optional>
#include <string>
#include <nlohmann/json.hpp>

namespace wpa3_tester{

enum class RewriteMode { none, errors, all };

struct Run_Config {
	std::optional<bool>        delete_old;
	std::optional<bool>        test_report;
	std::optional<bool>        only_stats;
	std::optional<RewriteMode> rewrite;
	std::optional<bool>        compile_external;
	std::optional<bool>        install_req;

	[[nodiscard]] bool        get_delete_old()       const { return delete_old.value_or(false); }
	[[nodiscard]] bool        get_test_report()      const { return test_report.value_or(false); }
	[[nodiscard]] bool        get_only_stats()       const { return only_stats.value_or(false); }
	[[nodiscard]] RewriteMode get_rewrite()          const { return rewrite.value_or(RewriteMode::none); }
	[[nodiscard]] bool        get_compile_external() const { return compile_external.value_or(false); }
	[[nodiscard]] bool        get_install_req()      const { return install_req.value_or(false); }

	void merge_from(const Run_Config &other){
		if(other.delete_old.has_value())       delete_old       = other.delete_old;
		if(other.test_report.has_value())      test_report      = other.test_report;
		if(other.only_stats.has_value())       only_stats       = other.only_stats;
		if(other.rewrite.has_value())          rewrite          = other.rewrite;
		if(other.compile_external.has_value()) compile_external = other.compile_external;
		if(other.install_req.has_value())      install_req      = other.install_req;
	}
};

inline void parse_run_config(const nlohmann::json &cfg, Run_Config &rc){
	if(cfg.contains("only_stats"))       rc.only_stats       = cfg.at("only_stats").get<bool>();
	if(cfg.contains("delete_old"))       rc.delete_old       = cfg.at("delete_old").get<bool>();
	if(cfg.contains("test_report"))      rc.test_report      = cfg.at("test_report").get<bool>();
	if(cfg.contains("compile_external")) rc.compile_external = cfg.at("compile_external").get<bool>();
	if(cfg.contains("install_req"))      rc.install_req      = cfg.at("install_req").get<bool>();
	if(cfg.contains("rewrite") && cfg.at("rewrite").is_string()){
		const auto &rw = cfg.at("rewrite").get_ref<const std::string &>();
		if(rw == "errors")     rc.rewrite = RewriteMode::errors;
		else if(rw != "false") rc.rewrite = RewriteMode::all;
	}
}

}
