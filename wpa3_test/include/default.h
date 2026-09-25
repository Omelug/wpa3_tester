#pragma once

inline char CSV_SEP = '|';

inline std::string TESTER_NAME = "wpa3_tester";
inline std::string DATA_DIR = "data";
inline std::string DEVICES_DIR = "devices";
inline std::string DATA_TEST = "test_data";
inline std::string DATA_SUITE = "suite_data";

// if changed -> change yaml test validator as well
// attack_config/validator/test_validator.schema.yaml (_actor_filler rule)
inline std::string ACTOR_FILLER_SUFFIX = "_actor_filler.yaml";

// data / output
inline std::string REPORT_NAME = "report.md";
inline std::string INDEX_HTML = "index.html";
inline std::string RESULT_NAME = "result.json";

//this actor name is
// if changed -> change test validator
inline std::string COMBINED = "combined";
inline std::string COMBINED_LOG = COMBINED + ".log";
inline std::string TESTER_LOG = "tester.log";
inline std::string TEST_CONFIG_NAME = "test_config.yaml";
inline std::string TEST_SUITE_CONFIG_DIR = "test_config";

// in test folder
inline std::string ERROR_FILE = "errors.txt";
inline std::string DONE_FILE = "done.txt";

inline std::string MAPPING_CSV = "mapping.csv";
inline std::string MAP_CSV_SEP = ",";
