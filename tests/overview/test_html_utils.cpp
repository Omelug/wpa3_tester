#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <filesystem>
#include <sstream>
#include <vector>
#include <doctest/doctest.h>
#include "overview/html_guard.h"
#include "overview/html_utils.h"

using namespace wpa3_tester;
using namespace std;
using namespace filesystem;

TEST_CASE("HtmlPathTable basic functionality") {
    path test_dir = temp_directory_path() / "html_utils_test";
    create_directories(test_dir);

	{
    	overview::HtmlGuard hg(test_dir);

    	struct TestEntry {
    		int id;
    		string name;
    		double value;
    	};
		vector<TestEntry> entries = {
			{1, "Alice", 95.5},
			{2, "Bob", 87.2},
			{3, "Charlie", 92.0}
		};
		HtmlPathTable table(hg, entries);

    	table.add_column("ID", [](const TestEntry& e) { return e.id; });
    	table.add_column("Name", [](const TestEntry& e) { return e.name; });
    	table.add_column("Score", [](const TestEntry& e) { return e.value; });
    	table.render();
	}

    path index_file = test_dir / "index.html";
    CHECK(exists(index_file));

    ifstream file(index_file);
    ostringstream oss;
    oss << file.rdbuf();
    string result = oss.str();

    CHECK(result.contains("<table"));
    CHECK(result.contains("<th>ID</th>"));
    CHECK(result.contains("<th>Name</th>"));
    CHECK(result.contains("<th>Score</th>"));
    CHECK(result.contains("<td>1</td>"));
    CHECK(result.contains("<td>Alice</td>"));
    CHECK(result.contains("<td>95.5</td>"));
	remove_all(test_dir);
}

TEST_CASE("HtmlPathTable with member access") {
    path test_dir = temp_directory_path() / "html_utils_test2";
    create_directories(test_dir);

	{
		overview::HtmlGuard hg(test_dir);

    	struct TestEntry {
    		int id;
    		string name;
    		double value;
    	};

    	vector<TestEntry> entries = {
    		{1, "Alice", 95.5},
			{2, "Bob", 87.2}
    	};

    	HtmlPathTable table(hg, entries);

    	table.add_column("ID", &TestEntry::id);
    	table.add_column("Name", &TestEntry::name);
    	table.add_column("Score", &TestEntry::value);
    	table.render();
	}

    path index_file = test_dir / "index.html";
    CHECK(exists(index_file));

    ifstream file(index_file);
    ostringstream oss;
    oss << file.rdbuf();
    string result = oss.str();

    CHECK(result.contains("<table"));
    CHECK(result.contains("<th>ID</th>"));
    CHECK(result.contains("<th>Name</th>"));
    CHECK(result.contains("<th>Score</th>"));
    CHECK(result.contains("<td>1</td>"));
    CHECK(result.contains("<td>Alice</td>"));
    CHECK(result.contains("<td>95.5</td>"));

	remove_all(test_dir);
}

TEST_CASE("HtmlPathTable with builder pattern") {
    path test_dir = temp_directory_path() / "html_utils_test3";
    create_directories(test_dir);
	{
		overview::HtmlGuard hg(test_dir);

    	struct TestEntry {
    		int id;
    		string name;
    		double value;
    	};

    	vector<TestEntry> entries = {
    		{1, "Alice", 95.5}
    	};

    	HtmlPathTable table(hg, entries);

    	table.build([&](auto col) {
			col("ID", &TestEntry::id);
			col("Name", &TestEntry::name);
			col("Score", &TestEntry::value);
		});
    	table.render();
	}

    path index_file = test_dir / "index.html";
    CHECK(exists(index_file));

    ifstream file(index_file);
    ostringstream oss;
    oss << file.rdbuf();
    string result = oss.str();

    CHECK(result.contains("<table"));
    CHECK(result.contains("<th>ID</th>"));
    CHECK(result.contains("<th>Name</th>"));
    CHECK(result.contains("<th>Score</th>"));
    CHECK(result.contains("<td>1</td>"));
    CHECK(result.contains("<td>Alice</td>"));
    CHECK(result.contains("<td>95.5</td>"));
	remove_all(test_dir);
}

TEST_CASE("HtmlPathTable prefix grouping functionality") {
	path test_dir = temp_directory_path() / "html_utils_test_prefix";
	create_directories(test_dir);

	{
		overview::HtmlGuard hg(test_dir);

		struct TestEntry {
			string test_name;
			string status;
			double score;
		};

		vector<TestEntry> entries = {
			{"channel_switch_rogueAP_internal_34e1cfeb", "pass", 95.5},
			{"channel_switch_rogueAP_internal_MFP_req_34e1cfeb", "pass", 87.2},
			{"channel_switch_rogueAP_WPA2_internal_MFP_bccf2bff", "fail", 92.0}
		};

		HtmlPathTable table(hg, entries);

		table.add_column("Test Name", [](const TestEntry& e) { return e.test_name; });
		table.add_column("Status", [](const TestEntry& e) { return e.status; });
		table.add_column("Score", [](const TestEntry& e) { return e.score; });
		table.render({"Test Name"}, "aggregate");
	}

	path index_file = test_dir / "index.html";
	CHECK(exists(index_file));

	ifstream file(index_file);
	ostringstream oss;
	oss << file.rdbuf();
	string result = oss.str();

	CHECK(result.contains("<table"));
	CHECK(result.contains("channel_switch_rogueAP_*"));
	CHECK(result.contains("internal_34e1cfeb"));
	CHECK(result.contains("internal_MFP_req_34e1cfeb"));
	CHECK(result.contains("WPA2_internal_MFP_bccf2bff"));

	remove_all(test_dir);
}
