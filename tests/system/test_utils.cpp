#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <filesystem>
#include <fstream>
#include <regex>
#include <string>
#include <thread>
#include <doctest/doctest.h>

#include "logger/error_log.h"
#include "system/utils.h"

using namespace std;
using namespace wpa3_tester;
using namespace filesystem;

TEST_CASE("current_time_string - format validation"){
    string time_str = current_time_string();

    regex time_pattern(R"(^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$)");
    CHECK(regex_match(time_str, time_pattern));

    CHECK_EQ(time_str.length(), 19);

    CHECK_EQ(time_str[4], '-');
    CHECK_EQ(time_str[7], '-');
    CHECK_EQ(time_str[10], ' ');
    CHECK_EQ(time_str[13], ':');
    CHECK_EQ(time_str[16], ':');
}

TEST_CASE("current_time_string - reasonable values"){
    string time_str = current_time_string();

    int year   = stoi(time_str.substr(0, 4));
    int month  = stoi(time_str.substr(5, 2));
    int day    = stoi(time_str.substr(8, 2));
    int hour   = stoi(time_str.substr(11, 2));
    int minute = stoi(time_str.substr(14, 2));
    int second = stoi(time_str.substr(17, 2));

    CHECK((year >= 2020 && year <= 2030));
    CHECK((month >= 1 && month <= 12));
    CHECK((day >= 1 && day <= 31));
    CHECK((hour >= 0 && hour <= 23));
    CHECK((minute >= 0 && minute <= 59));
    CHECK((second >= 0 && second <= 59));
}

TEST_CASE("current_time_string - consistency"){
    string time1 = current_time_string();
    this_thread::sleep_for(chrono::milliseconds(100));
    string time2 = current_time_string();
    CHECK_EQ(time1.length(), time2.length());
    CHECK((time2 >= time1));
}

TEST_CASE("relative_from - basic functionality"){
    path test_base = current_path() / "test_relative_base";
    path attack_config = test_base / "attack_config" / "subdir" / "nested" / TEST_CONFIG_NAME;
    create_directories(attack_config.parent_path());

    string result = relative_from("attack_config", attack_config);
    CHECK_EQ(result, "subdir/nested");

    remove_all(test_base);
}

TEST_CASE("relative_from - direct child"){
    path test_base = current_path() / "test_relative_direct";
    path attack_config = test_base / "attack_config" / "direct_config.yaml";
    create_directories(attack_config.parent_path());

    string result = relative_from("attack_config", attack_config);
    CHECK_EQ(result, ".");
    remove_all(test_base);
}

TEST_CASE("relative_from - base not found"){
    path test_base = current_path() / "test_relative_notfound";
    path other_dir = test_base / "other_directory" / "config.yaml";
    create_directories(other_dir.parent_path());

    CHECK_THROWS_AS(relative_from("attack_config", other_dir), wpa3_tester::config_err);

    remove_all(test_base);
}

TEST_CASE("relative_from - complex nested structure"){
    path test_base = current_path() / "test_relative_complex";
    path attack_config = test_base / "project" / "attack_config" / "Enterprise" / "reflection_attack" / "test.yaml";
    create_directories(attack_config.parent_path());

    string result = relative_from("attack_config", attack_config);
    CHECK_EQ(result, "Enterprise/reflection_attack");
    remove_all(test_base);
}

TEST_CASE("relative_from - absolute path handling"){
    path test_base = current_path() / "test_relative_absolute";
    path attack_config = test_base / "attack_config" / "absolute_test.yaml";
    create_directories(attack_config.parent_path());

    string abs_path = absolute(attack_config).string();
    string result = relative_from("attack_config", abs_path);
    CHECK_EQ(result, ".");
    remove_all(test_base);
}

TEST_CASE("relative_from - single level nesting"){
    path test_base = current_path() / "test_relative_single";
    path attack_config = test_base / "attack_config" / "single" / "config.yaml";
    create_directories(attack_config.parent_path());

    string result = relative_from("attack_config", attack_config);
    CHECK_EQ(result, "single");
    remove_all(test_base);
}

TEST_CASE("create_public_dirs - new directories and file are world-accessible"){
    const path test1 = path("/tmp/test_create_public_dirs") / "test1";
    const path test2 = test1 / "test2";
    remove_all(test1);

    create_public_dirs(test2);

    // Write a file and set its permissions
    const path test3 = test2 / "test3.txt";
    { ofstream f(test3); f << "x"; }
    set_public_perms(test3);

    // All directories must have rwxrwxrwx (0777)
	constexpr auto dir_expected = perms::all;
    CHECK_EQ(status(test1).permissions() & dir_expected, dir_expected);
    CHECK_EQ(status(test2).permissions() & dir_expected, dir_expected);

    // File must have rw-rw-rw- (0666)
	constexpr perms file_expected = perms::owner_read | perms::owner_write |
                                perms::group_read | perms::group_write |
                                perms::others_read | perms::others_write;
    CHECK_EQ(status(test3).permissions() & file_expected, file_expected);

    remove_all(test1);
}
