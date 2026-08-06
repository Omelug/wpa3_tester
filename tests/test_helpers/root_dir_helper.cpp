#include "root_dir_helper.h"
#include <fstream>
#include "config/global_config.h"
#include "system/utils.h"

namespace wpa3_tester::test_helpers{
using namespace std;
namespace fs = filesystem;

IsolatedRootDir::IsolatedRootDir(const string &name): real_root(root_dir()){
	const fs::path test_root = fs::temp_directory_path() / ("wpa3_tester_" + name);
	fs::remove_all(test_root);
	// mirrors the real layout (<repo>/wpa3_test is root_dir()) so root_dir().parent_path()
	// lands under test_root too -> anything under data/... that code-under-test creates
	// stays isolated and is removed in one shot below.
	dir = test_root / "wpa3_test";
	fs::create_directories(dir / "attack_config");

	ofstream(dir / "attack_config" / "global_config.yaml") << "actors: {}\n";

	// config_validation() (RunStatus/RunSuiteStatus constructors) needs the real schema files
	// under attack_config/validator/ (test_validator.schema.yaml, run_config.schema.yaml, and
	// whatever they $ref) -- symlink that whole tree in rather than hand-writing a fixture copy.
	const fs::path real_validator = real_root / "attack_config" / "validator";
	if(fs::exists(real_validator))
		fs::create_directory_symlink(real_validator, dir / "attack_config" / "validator");

	root_dir(dir);
	get_global_config(dir, true);
}

IsolatedRootDir::~IsolatedRootDir(){
	root_dir(real_root);
	get_global_config(real_root, true);
	error_code ec;
	fs::remove_all(dir.parent_path(), ec);
}
}
