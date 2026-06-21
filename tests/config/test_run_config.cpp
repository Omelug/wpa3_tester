#include <doctest.h>
#include <nlohmann/json.hpp>
#include "config/Run_Config.h"

using namespace wpa3_tester;
using namespace nlohmann;
using namespace std;

TEST_CASE("Run_Config default false"){
    Run_Config rc;
    CHECK_FALSE(rc.get_delete_old());
    CHECK_FALSE(rc.get_test_report());
    CHECK_FALSE(rc.get_only_stats());
    CHECK_FALSE(rc.get_compile_external());
    CHECK_FALSE(rc.get_install_req());
    CHECK_EQ(rc.get_rewrite(), RewriteMode::none);
}

TEST_CASE("parse_run_config - true bool fields"){
    Run_Config rc;
    parse_run_config(json{
        {"delete_old", true},
        {"test_report", true},
        {"only_stats", true},
        {"compile_external", true},
        {"install_req", true},
    }, rc);
    CHECK(rc.get_delete_old());
    CHECK(rc.get_test_report());
    CHECK(rc.get_only_stats());
    CHECK(rc.get_compile_external());
    CHECK(rc.get_install_req());
}

TEST_CASE("parse_run_config - rewrite modes"){
    auto parse_rewrite = [](const string &val){
        Run_Config rc;
        parse_run_config(json{{"rewrite", val}}, rc);
        return rc.get_rewrite();
    };

    CHECK_EQ(parse_rewrite("false"), RewriteMode::none);
    CHECK_EQ(parse_rewrite("errors"), RewriteMode::errors);
    CHECK_EQ(parse_rewrite("all"), RewriteMode::all);
    CHECK_EQ(parse_rewrite("true"), RewriteMode::all);
}

TEST_CASE("parse_run_config - absent fields stay nullopt"){
    Run_Config rc;
    parse_run_config(json{{"delete_old", true}}, rc);
    CHECK(rc.delete_old.has_value());
    CHECK_FALSE(rc.only_stats.has_value());
    CHECK_FALSE(rc.rewrite.has_value());
}

TEST_CASE("merge_from - set fields override, unset do not"){
    Run_Config base;
    parse_run_config(json{{"only_stats", true}, {"delete_old", true}}, base);

    Run_Config overlay;
    parse_run_config(json{{"only_stats", false}}, overlay);

    base.merge_from(overlay);
    CHECK_FALSE(base.get_only_stats());
    CHECK(base.get_delete_old());
}

TEST_CASE("merge_from - nullopt fields leave target unchanged"){
    Run_Config base;
    parse_run_config(json{{"rewrite", "all"}, {"install_req", true}}, base);

    Run_Config overlay;
    base.merge_from(overlay);

    CHECK_EQ(base.get_rewrite(), RewriteMode::all);
    CHECK(base.get_install_req());
}
