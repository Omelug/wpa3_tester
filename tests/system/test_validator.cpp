#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>
#include "setup/YAMLValidator.h"

using namespace std;
using namespace filesystem;

struct ValidatorFixture{
    path dir;

    explicit ValidatorFixture(const string &name): dir(temp_directory_path() / name){
        create_directories(dir);
    }

    void write(const string &filename, const string &content) const{
        ofstream f(dir / filename);
        f << content;
    }

    path schema(const string &filename = "schema.yaml") const{
        return dir / filename;
    }

    ~ValidatorFixture(){ remove_all(dir); }
};

TEST_CASE (
"YAMLValidator - basic validation passes"
)
 {
    ValidatorFixture f("validator_basic");
    f.write("schema.yaml", R"(
type: object
properties:
  name:
    type: string
required: [name]
)");
    nlohmann::json config = {{"name", "test"}};
    YAMLValidator validator(f.schema());
    CHECK_NOTHROW(validator.validate(config));
}

TEST_CASE (
"YAMLValidator - validation fails on wrong type"
)
 {
    ValidatorFixture f("validator_wrong_type");
    f.write("schema.yaml", R"(
type: object
properties:
  channel:
    type: integer
required: [channel]
)");
    nlohmann::json config = {{"channel", "not_an_int"}};
    YAMLValidator validator(f.schema());
    CHECK_THROWS(validator.validate(config));
}

TEST_CASE (
"YAMLValidator - apply_defaults fills missing fields"
)
 {
    ValidatorFixture f("validator_defaults");
    f.write("schema.yaml", R"(
type: object
properties:
  ieee80211w:
    type: integer
    default: 1
  channel:
    type: integer
    default: 6
)");
    nlohmann::json config = nlohmann::json::object();
    YAMLValidator validator(f.schema());
    validator.validate(config);

    CHECK_EQ(config["ieee80211w"], 1);
    CHECK_EQ(config["channel"], 6);
}

TEST_CASE (
"YAMLValidator - apply_defaults does not overwrite existing values"
)
 {
    ValidatorFixture f("validator_no_overwrite");
    f.write("schema.yaml", R"(
type: object
properties:
  channel:
    type: integer
    default: 6
)");
    nlohmann::json config = {{"channel", 11}};
    YAMLValidator validator(f.schema());
    validator.validate(config);

    CHECK_EQ(config["channel"], 11);
}

TEST_CASE (
"YAMLValidator - apply_defaults nested object"
)
 {
    ValidatorFixture f("validator_nested");
    f.write("schema.yaml", R"(
type: object
properties:
  setup:
    type: object
    properties:
      ieee80211w:
        type: integer
        default: 2
)");
    nlohmann::json config = {{"setup", nlohmann::json::object()}};
    YAMLValidator validator(f.schema());
    validator.validate(config);

    CHECK_EQ(config["setup"]["ieee80211w"], 2);
}

TEST_CASE (
"YAMLValidator - apply_defaults object default value"
)
 {
    ValidatorFixture f("validator_obj_default");
    f.write("schema.yaml", R"(
type: object
properties:
  options:
    type: object
    default:
      retries: 3
      timeout: 30
)");
    nlohmann::json config = nlohmann::json::object();
    YAMLValidator validator(f.schema());
    validator.validate(config);

    CHECK_EQ(config["options"]["retries"], 3);
    CHECK_EQ(config["options"]["timeout"], 30);
}

TEST_CASE (
"YAMLValidator - external schema ref"
)
 {
    ValidatorFixture f("validator_ref");
    f.write("base.yaml", R"(
type: object
properties:
  ssid:
    type: string
required: [ssid]
)");
    f.write("schema.yaml", R"(
type: object
properties:
  network:
    $ref: './base.yaml'
)");
    nlohmann::json config = {{"network", {{"ssid", "test"}}}};
    YAMLValidator validator(f.schema());
    CHECK_NOTHROW(validator.validate(config));
}

TEST_CASE (
"YAMLValidator - missing required field throws"
)
 {
    ValidatorFixture f("validator_required");
    f.write("schema.yaml", R"(
type: object
properties:
  ssid:
    type: string
required: [ssid]
)");
    nlohmann::json config = nlohmann::json::object();
    YAMLValidator validator(f.schema());
    CHECK_THROWS(validator.validate(config));
}

TEST_CASE (
"YAMLValidator - schema file not found throws"
)
 {
    CHECK_THROWS(YAMLValidator(temp_directory_path() / "nonexistent.yaml"));
}