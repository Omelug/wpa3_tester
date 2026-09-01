#include "visual/DoS_hard/sae_dos/sae_dos_entry.h"

#include <filesystem>
#include <set>
#include "default.h"
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::sae_dos {
using namespace std;
using namespace filesystem;

static const set<string> k_sae_dos_modules = {
	"sae_dos_wrapper", "cookie_guzzler", "memory_omnivore", "pmk_gobbler", "bad_status_code", "double_decker", "bad_seq"
};

SaeDosFolderEntry SaeDosFolderEntry::parse(const path &test_folder) {
	SaeDosFolderEntry e;
	e.test_folder = test_folder;
	e.name = test_folder.filename().string();
	const auto png = test_folder / "observer" / "resource_checker" / "ap_res.png";
	if (exists(png))
		e.ap_res_png = png;
	return e;
}

std::vector<SaeDosFolderEntry> SaeDosFolderEntry::collect_results(const path &suite_data_dir,
	const string &module_filter) {
	vector<SaeDosFolderEntry> entries;
	for (const auto &attack_dir : directory_iterator(suite_data_dir)) {
		if (!attack_dir.is_directory()) continue;
		if (module_filter == "sae_dos_wrapper" && attack_dir.path().filename() != "dos_attacks_gen")
			continue;
		for (const auto &entry : directory_iterator(attack_dir.path())) {
			if (!entry.is_directory()) continue;
			if (!exists(entry.path() / TEST_CONFIG_NAME)) continue;
			const auto mod = helper::read_attacker_module_field(entry.path());
			if (!module_filter.empty() && module_filter != "sae_dos_wrapper") {
				if (mod != module_filter) continue;
			} else if (!k_sae_dos_modules.contains(mod)) {
				continue;
			}
			entries.push_back(parse(entry.path()));
		}
	}
	return entries;
}

void SaeDosFolderEntry::render_table(overview::HtmlGuard &f, const string &module,
	const path &suite_data_dir, const path &page_dir, const string &t_name){

	helper::div_card<SaeDosFolderEntry>(f, module, suite_data_dir, [&](overview::HtmlGuard& hg,
		const std::vector<SaeDosFolderEntry>& entries) {

		HtmlPathTable t(hg, entries, t_name);
		#define COL(name, body) col(name, [&]( [[maybe_unused]] const auto& e) { body; })
		t.build([&](auto col) {
			COL("Test", hg << overview::test_name_cell(e.test_folder, e.name, page_dir));
			COL("AP Resources",
				if (!e.ap_res_png.empty()){
					hg << R"(<img src=")" << filesystem::relative(e.ap_res_png, page_dir).string() << R"(" style="max-height:160px;">)";
				}else{
					hg << "-";
				}
			);
		})->render({"Test"});
		#undef COL
	}, t_name);
}

}
