#include "suite/DoS_hard/sae_dos/sae_dos_entry.h"

#include <filesystem>
#include "overview/html_guard.h"

namespace wpa3_tester::suite::sae_dos {
using namespace std;
using namespace filesystem;

SaeDosFolderEntry SaeDosFolderEntry::parse(const path &test_folder) {
    SaeDosFolderEntry e;
    e.name = test_folder.filename().string();
    const auto png = test_folder / "observer" / "resource_checker" / "access_point_res.png";
    if (exists(png))
        e.ap_res_png = png;
    return e;
}

void SaeDosFolderEntry::render_table(overview::HtmlGuard &f,
                                     const vector<path> &folders,
                                     const path &page_dir) {
    f << "        <table>\n"
      << "            <thead><tr><th>Test</th><th>AP Resources</th></tr></thead>\n"
      << "            <tbody>\n";
    for (const auto &p : folders) {
        const auto e = parse(p);
        f << "                <tr>\n"
          << "                    <td>" << overview::test_name_cell(p, e.name, page_dir) << "</td>\n"
          << "                    <td>";
        if (!e.ap_res_png.empty())
            f << "<img src=\"" << e.ap_res_png << "\" style=\"max-height:160px;\">";
        else
            f << "—";
        f << "</td>\n"
          << "                </tr>\n";
    }
    f << "            </tbody>\n        </table>\n";
}

}
