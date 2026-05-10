#pragma once

namespace wpa3_tester{
enum class RewriteMode { none, errors, all };
struct Run_Config {
	// test_suite_only
	bool delete_old  = false;
	bool test_report = false;
	bool only_stats = false;
	// (global defaults overridden by test_suited
	RewriteMode rewrite          = RewriteMode::none;
	bool        compile_external = false;
	bool        install_req      = false;
};
}