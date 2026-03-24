#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <fstream>
#include <filesystem>
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "scan/scan.h"

using namespace std;
using namespace wpa3_tester;
using namespace  filesystem;

TEST_CASE("RunStatus::setup_test - directory management") {
    const path test_run_folder = temp_directory_path() / "test_setup_run";
    
    SUBCASE("Creates and cleans run folder") {
        create_directories(test_run_folder);
        ofstream test_file(test_run_folder / "existing_file.txt");
        test_file << "test content";
        test_file.close();
        
        REQUIRE(exists(test_run_folder));
        REQUIRE(exists(test_run_folder / "existing_file.txt"));
        
        RunStatus rs;
        rs.run_folder = test_run_folder.string();
        rs.config["attacker_module"] = "nonexistent_module";
        
        REQUIRE_NOTHROW(rs.setup_test());
        
        REQUIRE(exists(test_run_folder));
        REQUIRE_FALSE(exists(test_run_folder / "existing_file.txt"));
        remove_all(test_run_folder);
    }
    
    SUBCASE("Handles non-existent directory") {
        REQUIRE_FALSE(exists(test_run_folder));
        
        RunStatus rs;
        rs.run_folder = test_run_folder.string();
        rs.config["attacker_module"] = "nonexistent_module";
        
        REQUIRE_NOTHROW(rs.setup_test());
        REQUIRE(exists(test_run_folder));
        remove_all(test_run_folder);
    }
}

TEST_CASE("get_actors_conn_table - basic parsing") {
    const path test_file = temp_directory_path() / "test_conn_table.csv";

    SUBCASE("Valid file with required columns") {
        ofstream out(test_file);
        out << "whitebox_host,whitebox_ip,external_OS\n";
        out << "router1,192.168.1.1,openwrt\n";
        out << "laptop,192.168.1.100,ddwrt\n";
        out.close();

        auto result = scan::get_actors_conn_table(test_file);

        CHECK((result.size() == 2));
        CHECK((result[0]->str_con["whitebox_host"].value() == "router1"));
        CHECK((result[0]->str_con["whitebox_ip"].value() == "192.168.1.1"));
        CHECK((result[0]->str_con["external_OS"].value() == "openwrt"));

        CHECK((result[1]->str_con["whitebox_host"].value() == "laptop"));
        CHECK((result[1]->str_con["whitebox_ip"].value() == "192.168.1.100"));
        CHECK((result[1]->str_con["external_OS"].value() == "ddwrt"));

        remove(test_file);
    }

    SUBCASE("File with whitespace trimming") {
        ofstream out(test_file);
        out << " whitebox_host , whitebox_ip \n";
        out << " router1 , 192.168.1.1 \n";
        out.close();

        auto result = scan::get_actors_conn_table(test_file);

        CHECK((result.size() == 1));
        CHECK((result[0]->str_con["whitebox_host"].value() == "router1"));
        CHECK((result[0]->str_con["whitebox_ip"].value() == "192.168.1.1"));

        remove(test_file);
    }
}

TEST_CASE("get_actors_conn_table - error cases") {
    const path test_file = temp_directory_path() / "test_conn_table_err.csv";

    SUBCASE("Non-existent file returns empty vector") {
        const path non_existent = temp_directory_path() / "does_not_exist.csv";
        auto result = scan::get_actors_conn_table(non_existent);
        CHECK(result.empty());
    }

    SUBCASE("Missing whitebox_host column throws") {
        ofstream out(test_file);
        out << "whitebox_ip,external_OS\n";
        out << "192.168.1.1,OpenWrt\n";
        out.close();
        CHECK_THROWS_AS(scan::get_actors_conn_table(test_file), config_err);
        remove(test_file);
    }

    SUBCASE("Missing whitebox_ip column throws") {
        ofstream out(test_file);
        out << "whitebox_host,external_OS\n";
        out << "router1,OpenWrt\n";
        out.close();
        CHECK_THROWS_AS(scan::get_actors_conn_table(test_file), config_err);
        remove(test_file);
    }

    SUBCASE("Empty file throws") {
        ofstream out(test_file);
        out.close();
        CHECK_THROWS_AS(scan::get_actors_conn_table(test_file), config_err);
        remove(test_file);
    }
}

TEST_CASE("get_actors_conn_table - edge cases") {
    const path test_file = temp_directory_path() / "test_conn_table_edge.csv";

    SUBCASE("Different column order") {
        ofstream out(test_file);
        out << "external_OS,whitebox_ip,whitebox_host\n";
        out << "OpenWrt,192.168.1.1,router1\n";
        out.close();

        auto result = scan::get_actors_conn_table(test_file);

        CHECK((result.size() == 1));
        CHECK((result[0]->str_con["whitebox_host"].value() == "router1"));
        CHECK((result[0]->str_con["whitebox_ip"].value() == "192.168.1.1"));
        CHECK((result[0]->str_con["external_OS"].value() == "OpenWrt"));

        remove(test_file);
    }

    SUBCASE("Empty field values") {
        ofstream out(test_file);
        out << "whitebox_host,whitebox_ip,external_OS\n";
        out << "router1,192.168.1.1,\n";
        out.close();

        auto result = scan::get_actors_conn_table(test_file);
        CHECK((result.size() == 1));
        CHECK((result[0]->str_con["whitebox_host"].value() == "router1"));
        CHECK((result[0]->str_con["whitebox_ip"].value() == "192.168.1.1"));
        CHECK_FALSE((result[0]->str_con["external_OS"].has_value()));

        remove(test_file);
    }
}

