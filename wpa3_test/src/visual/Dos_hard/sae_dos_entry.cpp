#include "visual/DoS_hard/sae_dos/sae_dos_entry.h"

#include <filesystem>
#include "overview/html_guard.h"
#include "overview/html_utils.h"
#include "visual/suite_helper.h"

namespace wpa3_tester::visual::sae_dos {
using namespace std;
using namespace filesystem;

SaeDosFolderEntry SaeDosFolderEntry::parse(const path &test_folder) {
	SaeDosFolderEntry e;
	e.test_folder = test_folder;
	e.name = test_folder.filename().string();
	const auto png = test_folder / "observer" / "resource_checker" / "ap_res.png";
	if (exists(png))
		e.ap_res_png = png;
	return e;
}

void SaeDosFolderEntry::render_table(overview::HtmlGuard &f, const string &title,
	const path &suite_data_dir, const path &page_dir){

	helper::div_card<SaeDosFolderEntry>(f, title, suite_data_dir, [&](overview::HtmlGuard& hg,
		const std::vector<SaeDosFolderEntry>& entries) {

			HtmlPathTable t(hg, entries);
			#define COL(name, body) col(name, [&]( [[maybe_unused]] const auto& e) { body; })
			t.build([&](auto col) {
				COL("Test",	f << overview::test_name_cell(e.test_folder, e.name, page_dir));
				COL("AP Resources",
				if (!e.ap_res_png.empty()){
					hg << R"(<img src=")" << e.ap_res_png << R"(" style="max-height:160px;">)";
				}else{
					hg << "—";
				};
			);
			})->render();
			#undef COL
	});
}

}
