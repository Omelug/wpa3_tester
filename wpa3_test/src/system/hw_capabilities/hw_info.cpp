#include "system/hw_info.h"

#include <fstream>

#include "attacks/mc_mitm/MonitorSocket.h"
#include "config/Actor_config.h"
#include "config/ActorPtr.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester{
using namespace std;
using namespace filesystem;


// Combine all tests whose name equals prefix or starts with prefix+"/"
static optional<InjectionTestResult> extract_test(
    const InjectionSuiteResult &suite, const string &prefix
){
    InjectionTestResult combined;
    combined.test_name = prefix;
    bool found = false;
    for(const auto &[test_name, flags, detail] : suite.tests){
        if(test_name == prefix || test_name.starts_with(prefix + "/")){
            combined.flags |= flags;
            if(!detail.empty()){
                if(!combined.detail.empty()) combined.detail += "; ";
                combined.detail += test_name + ": " + detail;
            }
            found = true;
        }
    }
    return found ? optional{combined} : nullopt;
}

// -----------------  InjectionTestResult / InjectionSuiteResult member implementations

nlohmann::json InjectionTestResult::to_json() const{
    return {{"name", test_name}, {"flags", flags}, {"detail", detail}};
}

InjectionTestResult InjectionTestResult::from_json(const nlohmann::json &j){
    return {j.value("name", ""), j.value("flags", 0), j.value("detail", "")};
}

nlohmann::json InjectionSuiteResult::to_json() const{
    nlohmann::json arr = nlohmann::json::array();
    for(const auto &t: tests) arr.push_back(t.to_json());
    return {{"driver", driver}, {"channel", channel.ch_num}, {"tests", arr}};
}


// -----------------  HwInfo


nlohmann::json HwInfo::to_json() const{
    nlohmann::json j = {
        {"driver_name",        actor->get(SK::driver_name)},
		{"driver_hash",        actor->get(SK::driver_hash)},
        {"permanent_mac", actor->get(SK::permanent_mac)},
    };
    j.update(actor->caps_to_flat_json());
    return j;
}

void HwInfo::from_json(const nlohmann::json &j){
    if(!actor) actor = make_shared<Actor_config>();
    actor->set(SK::driver_name, j.value("driver_name", ""));
	if(j.contains("driver_hash") && j.at("driver_hash").is_string() && !j.at("driver_hash").get<string>().empty())
		actor->set(SK::driver_hash, j.at("driver_hash").get<string>());
    actor->set(SK::permanent_mac, j.value("permanent_mac", ""));
    actor->caps_from_flat_json(j);
}

// -----------------  Actor_config::get_hw_info

void Actor_config::load_hw_info(const optional<path> &cache){
    const string iface     = get(SK::iface);
    const string perm_mac  = hw_capabilities::get_permanent_mac(iface, (*this)[SK::netns]);

	// ----- try cache -----
    if(cache.has_value() && exists(*cache)){
        try{
            ifstream f(*cache);
            const auto json_cache = nlohmann::json::parse(f);
            if(json_cache.contains(perm_mac)){ //perm_mac is cache key
                HwInfo hw_cached; hw_cached.actor = shared_from_this();
                hw_cached.from_json(json_cache.at(perm_mac));
                return;
            }
        } catch(const exception &e){
            log(LogLevel::WARNING, "get_hw_info: cache read failed ({}): {}", cache->string(), e.what());
        }
    }

    // ----- collect info -----
	set(SK::permanent_mac, perm_mac);
    set(SK::driver_name, hw_capabilities::get_driver_name(iface));
    set(SK::driver_hash, hw_capabilities::get_driver_hash(get(SK::driver_name)));

    ActorPtr self(shared_from_this());
    hw_capabilities::get_nl80211_caps(self);

    // ----- injection self-test -----
    if((*this)[BK::monitor].value_or(false)){
        constexpr Channel ch{11, WifiBand::BAND_2_4};
        try{
            hw_capabilities::setup_injection_iface(iface, ch, (*this)[SK::netns]);
            MonitorSocket sock(iface);
            const InjectionSuiteResult self_test = hw_capabilities::run_injection_tests(
                sock, iface, sock, ch,
                Tins::HWAddress<6>("00:11:22:33:44:55"),
                /*skip_mf=*/false,
                /*testack=*/false //FIXME no ack test?
            );
            //TODO store injection results
            (void)extract_test(self_test, "mf");
        } catch(const exception &e){
            log(LogLevel::WARNING, "get_hw_info: injection test failed for {}: {}", iface, e.what());
        }
    }

    // ----- write cache -----
    if(cache.has_value()){
    	//create cache
    	if (!exists(*cache)) {
    		ofstream create_file(*cache);
    		create_file.close();

    		permissions(*cache, perms::owner_read | perms::owner_write |
								perms::group_read | perms::group_write |
								perms::others_read | perms::others_write);
    	}

        try{
            create_directories(cache->parent_path());
            nlohmann::json json_cache = nlohmann::json::object();
            if(exists(*cache)){
                ifstream f(*cache);
                auto parsed = nlohmann::json::parse(f, nullptr, false);
                if(!parsed.is_discarded()) json_cache = parsed;
            }
            HwInfo hw_snapshot;
        	hw_snapshot.actor = shared_from_this();
            json_cache[perm_mac] = hw_snapshot.to_json();
            ofstream f(*cache);
            f << json_cache.dump(2) << '\n';
        } catch(const exception &e){
            log(LogLevel::WARNING, "get_hw_info: cache write failed: {}", e.what());
        }
    }
}
}
