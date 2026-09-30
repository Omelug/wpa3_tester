#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include "config/Actor_Config/Actor_Config_internal.h"
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "visual/suite_helper.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;
namespace json = nlohmann;

static ActorPtr make_actor(const string &perm_mac = "") {
	auto a = make_shared<Actor_Config_internal>();
	if(!perm_mac.empty()) a->set(SK::permanent_mac, perm_mac);
	return ActorPtr(a);
}

TEST_CASE("get_filler_hash - output format") {
	ActorMap m;
	m["sta"] = make_actor("aa:bb:cc:dd:ee:ff");
	json::json cfg;
	string h = RunStatus::get_filler_hash(m, cfg);
	CHECK_EQ(h.size(), 8u);
	CHECK_FALSE(h.empty());
	for(char c: h) CHECK(isxdigit(c));
}

TEST_CASE("get_filler_hash - determinism") {
	ActorMap m;
	m["ap"]  = make_actor("11:22:33:44:55:66");
	m["sta"] = make_actor("aa:bb:cc:dd:ee:ff");
	json::json cfg1, cfg2;
	CHECK_EQ(RunStatus::get_filler_hash(m, cfg1), RunStatus::get_filler_hash(m, cfg2));
}

TEST_CASE("get_filler_hash - order independence") {
	json::json cfg1, cfg2;

	ActorMap m1, m2;
	m1["alpha"] = make_actor("aa:aa:aa:aa:aa:aa");
	m1["beta"]  = make_actor("bb:bb:bb:bb:bb:bb");
	m2["beta"]  = make_actor("bb:bb:bb:bb:bb:bb");
	m2["alpha"] = make_actor("aa:aa:aa:aa:aa:aa");

	CHECK_EQ(RunStatus::get_filler_hash(m1, cfg1), RunStatus::get_filler_hash(m2, cfg2));
}

TEST_CASE("get_filler_hash - throws when actor has no permanent_mac") {
	ActorMap m;
	m["sta"] = make_actor(); // no permanent_mac
	json::json cfg;
	CHECK_THROWS_AS(RunStatus::get_filler_hash(m, cfg), wpa3_tester::run_err);
}

TEST_CASE("get_filler_hash - sets test_cfg actors selection") {
	ActorMap m;
	m["sta"] = make_actor("aa:bb:cc:dd:ee:ff");
	json::json cfg;
	RunStatus::get_filler_hash(m, cfg);
	CHECK_EQ(cfg["actors"]["sta"]["selection"]["permanent_mac"].get<string>(), "aa:bb:cc:dd:ee:ff");
}

TEST_CASE("get_filler_hash - different macs produce different hashes") {
	ActorMap m1, m2;
	m1["sta"] = make_actor("aa:bb:cc:dd:ee:ff");
	m2["sta"] = make_actor("11:22:33:44:55:66");
	json::json cfg1, cfg2;
	CHECK_NE(RunStatus::get_filler_hash(m1, cfg1), RunStatus::get_filler_hash(m2, cfg2));
}

TEST_CASE("change_filler_hash - no-op without filler suffix in config_path") {
	RunStatus rs;
	rs.config_path("/tmp/some_test.yaml"); // no ACTOR_FILLER_SUFFIX
	rs.config()["name"] = "test_deadbeef";

	ActorMap m;
	m["sta"] = make_actor("aa:bb:cc:dd:ee:ff");

	// ponytail: not calling methods that touch filesystem — only checking early-return path
	REQUIRE_NOTHROW(rs.change_filler_hash(m));
	CHECK_EQ(rs.config()["name"].get<string>(), "test_deadbeef"); // unchanged
}

TEST_CASE("change_filler_hash - no-op when hash unchanged") {
	const string suffix = ACTOR_FILLER_SUFFIX;
	const path tmp = temp_directory_path() / "filler_hash_test";
	create_directories(tmp);

	// hash of "sta=aa:bb:cc:dd:ee:ff" via std::hash<string>, first 8 hex chars
	const string hash = "7f2079bc";
	const string name = "test_" + hash;
	ActorMap m;
	m["sta"] = make_actor("aa:bb:cc:dd:ee:ff");

	const path cfg_path = tmp / (hash + suffix);
	ofstream(cfg_path) << "name: " + name + "\n";
	const path run_folder = tmp / name;
	create_directories(run_folder);

	RunStatus rs;
	rs.config_path(cfg_path);
	rs.config()["name"] = name;
	rs.run_folder(run_folder);

	REQUIRE_NOTHROW(rs.change_filler_hash(m));
	CHECK_EQ(rs.config()["name"].get<string>(), name); // unchanged
	CHECK(exists(run_folder));

	remove_all(tmp);
}
