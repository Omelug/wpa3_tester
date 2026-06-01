#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <set>
#include <string>
#include <vector>

#include "config/RunSuiteStatus.h"
#include "system/utils.h"

using namespace std;
using namespace filesystem;

namespace wpa3_tester::suite{

static const string PNG_TARGET = "access_point_res.png";
static const set<string> PATH_NOISE{"observer", "resource_checker"};

string section_title(const path &rel){
	string title;
	for(const auto &part: rel.parent_path()){
		if(PATH_NOISE.contains(part.string())) continue;
		if(!title.empty()) title += " / ";
		title += part.string();
	}
	return title;
}

void generate_suite_report(RunSuiteStatus &rss){
	const auto run_dir = rss.run_folder();
	ofstream report(run_dir / "report.md");
	if(!report.is_open()) return;

	report << "# Suite Report\n\n## Resource Usage\n\n";

	if(!exists(run_dir)){
		report << "_Run folder not found._\n\n";
		return;
	}

	vector<path> images;
	for(const auto &entry: recursive_directory_iterator(run_dir)){
		if(entry.is_regular_file() && entry.path().filename() == PNG_TARGET)
			images.push_back(entry.path());
	}
	ranges::sort(images);

	if(images.empty()){
		report << "_No resource data available._\n\n";
		return;
	}

	for(const auto &img: images){
		const auto rel = relative(img, run_dir);
		const auto title = section_title(rel);
		report << "### " << title << "\n\n";
		report << "![" << title << "](" << rel.generic_string() << ")\n\n";
	}
	report.close();
	set_public_perms(run_dir / "report.md");
}
}

