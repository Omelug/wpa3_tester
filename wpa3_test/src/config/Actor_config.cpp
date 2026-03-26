#include "config/Actor_config.h"
#include "config/ActorPtr.h"
#include "logger/error_log.h"
namespace wpa3_tester{
    using namespace std;
    using json = nlohmann::json;
    Actor_config::Actor_config(const json& j) {
        if (j.contains("selection") && j.at("selection").is_object()) {
            const auto& sel = j.at("selection");
            for (auto & [key, val] : str_con) {
                if (sel.contains(key) && sel[key].is_string()) {
                    if(key == "mac"){
                        set_mac(sel[key].get<string>());
                        continue;
                    }
                    val = sel[key].get<string>();
                }
            }

            if (sel.contains("condition") && sel.at("condition").is_array()) {
                for (const auto& cond_name : sel.at("condition")) {
                    if (auto key = cond_name.get<string>(); bool_conditions.contains(key)) {
                        bool_conditions[key] = true;
                    }
                }
            }
        }

        if (j.contains("netns")){str_con["netns"] = j.at("netns");}
        if (j.contains("source")){str_con["source"] = j.at("source");}
    }

    bool Actor_config::matches(const Actor_config& offer) {
        for (auto const & [key, required_val] : str_con) {
            if (!required_val.has_value()) { continue;}
            if (!offer.str_con.at(key).has_value()) { continue;}
            if (auto it = offer.str_con.find(key); it == offer.str_con.end() || it->second != required_val) {
                return false;
            }
        }

        // Check boolean conditions
        for(auto const& [key, required_val] : bool_conditions) {
            if (!required_val.has_value()) {continue;}
            if (!offer.bool_conditions.at(key).has_value()) { continue;}
            if (auto it = offer.bool_conditions.find(key);
                it == offer.bool_conditions.end() || it->second != required_val) {
                return false;
            }
        }
        return true;
    }

    Actor_config& Actor_config::operator+=(const Actor_config& other) {
        for (auto const& [key, val] : other.str_con) {
            if (!val.has_value()) continue;
            auto& mine = str_con[key];
            if (!mine.has_value()) {
                mine = val; // fill missing
            } else if (mine != val) {
                throw std::runtime_error("Actor_config conflict on key '"+key+"': '"
                    + mine.value()+"' vs '"+val.value()+"'");
            }
        }

        for (auto const& [key, val] : other.bool_conditions) {
            if (!val.has_value()) continue;
            auto& mine = bool_conditions[key];
            if (!mine.has_value()) {
                mine = val;
            } else if (mine != val) {
                throw std::runtime_error("Actor_config conflict on bool key '"+key+"'");
            }
        }
        return *this;
    }

    std::string Actor_config::operator[](const std::string& key) const {
        const auto it = str_con.find(key);
        if (it == str_con.end()) {
            throw config_err("Actor_config: missing required string condition '"+key+"'");
        }
        if (!it->second.has_value()) {
            throw config_err("Actor_config: string condition '"+key+"' has no value");
        }
        return *(it->second);
    }

    bool Actor_config::get_bool(const std::string& key) const {
        const auto it = bool_conditions.find(key);
        if (it == bool_conditions.end()) {
            throw config_err("Actor_config: missing required bool condition '"+key+"'");
        }
        if (!it->second.has_value()) {
            throw config_err("Actor_config: bool condition '"+key+"' has no value");
        }
        return *(it->second);
    }

    std::string Actor_config::to_str() const {
        string result;

        // string params
        bool first_str = true;
        for (const auto& [key, val] : str_con) {
            if (val.has_value()) {
                if (!first_str) result += ", ";
                result += key +"="+val.value();
                first_str = false;
            }
        }

        vector<string> true_conds;
        vector<string> false_conds;

        for (const auto& [key, val] : bool_conditions) {
            if (val.has_value()) {
                if (val.value()) {
                    true_conds.push_back(key);
                } else {
                    false_conds.push_back(key);
                }
            }
        }

        // True list
        if (!true_conds.empty()) {
            result += " True: [";
            for (size_t i = 0; i < true_conds.size(); ++i) {
                if (i > 0) result += ", ";
                result += true_conds[i];
            }
            result += "]";
        }

        // False list
        if (!false_conds.empty()) {
            result += " False: [";
            for (size_t i = 0; i < false_conds.size(); ++i) {
                if (i > 0) result += ", ";
                result += false_conds[i];
            }
            result += "]";
        }
        return result;
    }
    void Actor_config::print_ActorCMap(const std::string& title, const vector<ActorPtr> &actors){
        cout << title << ":\n";
        for (size_t i = 0; i < actors.size(); ++i) {
            cout << "[" << i << "] " << actors[i]->to_str() << "\n";
        }
        cout << flush;
    }
    void Actor_config::print_ActorCMap(const std::string& title, ActorCMap actors) {
        cout << title << ":\n";
        for (const auto& [key, actor_ptr] : actors) {
            const ActorPtr actor = actor_ptr;
            auto it = actor->str_con.find("whitebox_host");
            cout << "[" << key << "] "
                << (it != actor->str_con.end() && it->second.has_value() ? it->second.value() : "Actor_"+key)
                << " "
                << actor->to_str()
                << "\n";
        }
        cout << flush;
    }
    bool Actor_config::is_WB() const{
        return (str_con.at("source").value() == "internal") || is_external_WB();
    }
    bool Actor_config::is_external_WB() const{
        return str_con.at("source").value() == "external" &&
             (str_con.at("whitebox_host").has_value() || str_con.at("whitebox_ip").has_value());
    }
}
