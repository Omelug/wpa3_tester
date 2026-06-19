#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <cstdio>
#include <doctest.h>
#include <filesystem>
#include <unistd.h>
#include "config/Actor_Config/Actor_Config_sim.h"
#include "system/hw_capabilities.h"

using namespace std;
using namespace wpa3_tester;
namespace fs = filesystem;

static string iw_info(const string &iface){
    FILE *p = popen(("iw dev " + iface + " info 2>&1").c_str(), "r");
    if(!p) return {};
    string out; char buf[256];
    while(fgets(buf, sizeof(buf), p)) out += buf;
    pclose(p);
    return out;
}

static bool g_hwsim_ok = false;

static void load_hwsim(){
    static bool attempted = false;
    if(attempted) return;
    attempted = true;

    if(hw_capabilities::run_cmd({"modprobe", "mac80211_hwsim", "radios=2"}, nullopt, false) != 0)
        return;

    hw_capabilities::run_cmd({"udevadm", "settle"}, nullopt, false);
    for(const auto &[name, radio, type] : hw_capabilities::list_interfaces(InterfaceType::Wifi, nullopt))
        hw_capabilities::run_cmd({"ip", "link", "set", name, "name", HWSIM_IFACE_PREFIX + name}, nullopt, false);
    hw_capabilities::run_cmd({"udevadm", "settle"}, nullopt, false);

    g_hwsim_ok = !hw_capabilities::list_interfaces(InterfaceType::WifiVirtualHwsim, nullopt).empty();
    if(g_hwsim_ok)
        atexit([]{ hw_capabilities::run_cmd({"modprobe", "-r", "mac80211_hwsim"}, nullopt, false); });
}

// -----------------

struct HwsimFixture {
    bool ok = false;
    string iface;
    ActorPtr base;

    HwsimFixture(){
        load_hwsim();
        if(!g_hwsim_ok) return;

        const auto found = hw_capabilities::list_interfaces(InterfaceType::WifiVirtualHwsim, nullopt);
        const auto &[name, radio, type] = found[0];
        iface = name;

        const auto a = make_shared<Actor_Config_sim>();
        a->set(SK::mac,  "02:bb:cc:dd:ee:01");
        a->set(SK::iface, name);
        a->set(SK::radio, radio);
        base = ActorPtr(a);

        ok = true;
        reset();
    }

    ~HwsimFixture(){ if(ok) reset(); }

    [[nodiscard]] bool skip() const {
        if(!ok) MESSAGE("Skipping: mac80211_hwsim not available on this kernel");
        return !ok;
    }

    void reset() const {
        hw_capabilities::run_cmd({"ip",  "link", "set", iface, "down"}, nullopt, false);
        hw_capabilities::run_cmd({"iw",  "dev",  iface, "set", "type", "managed"}, nullopt, false);
    }

    [[nodiscard]] ActorPtr make_actor(const string &name = "test") const {
        const auto a = make_shared<Actor_Config_sim>(*base);
        a->set(SK::actor_name,    name);
        a->set(SK::permanent_mac, hw_capabilities::get_permanent_mac(iface, nullopt));
        return ActorPtr(a);
    }

    static nlohmann::json cfg(const string &name = "test", nlohmann::json extra = {}){
        return {{"actors", {{name, extra}}}};
    }
};

TEST_CASE("hwsim setup_actor - change mac address"){
    HwsimFixture f;
    if(f.skip()) return;

    const string new_mac = "02:bb:cc:dd:ee:01";
    auto actor = f.make_actor();
    actor->set(SK::mac, new_mac);

    actor->setup_actor(HwsimFixture::cfg(), f.base);

    CHECK_EQ(hw_capabilities::get_mac_address(f.iface, nullopt).to_string(), new_mac);
}

TEST_CASE("hwsim setup_actor - set AP mode"){
    HwsimFixture f;
    if(f.skip()) return;

    auto probe = f.make_actor();
    hw_capabilities::get_nl80211_caps(probe);
    if(!probe.get(BK::AP)){
        MESSAGE("Skipping: AP mode not supported by mac80211_hwsim on this kernel");
        return;
    }

    auto actor = f.make_actor();
    actor->set(BK::AP, true);

    actor->setup_actor(HwsimFixture::cfg(), f.base);

    CHECK_NE(iw_info(f.iface).find("type AP"), string::npos);
}

TEST_CASE("hwsim setup_actor - set managed mode"){
    HwsimFixture f;
    if(f.skip()) return;
    // start from monitor so the switch is meaningful
    hw_capabilities::run_cmd({"iw", "dev", f.iface, "set", "type", "monitor"}, nullopt, false);

    auto actor = f.make_actor();
    actor->set(BK::managed, true);

    actor->setup_actor(HwsimFixture::cfg(), f.base);

    CHECK_NE(iw_info(f.iface).find("type managed"), string::npos);
}

TEST_CASE("hwsim setup_actor - set monitor mode"){
    HwsimFixture f;
    if(f.skip()) return;

    auto actor = f.make_actor();
    actor->set(BK::monitor, true);

    actor->setup_actor(HwsimFixture::cfg(), f.base);

    // sysfs type 803 = ARPHRD_IEEE80211_RADIOTAP
    CHECK_EQ(hw_capabilities::read_sysfs(f.iface, "type"), "803");
}

TEST_CASE("hwsim setup_actor - set channel"){
    HwsimFixture f;
    if(f.skip()) return;

    auto actor = f.make_actor();
    actor->set(BK::monitor, true);
    actor->set(SK::channel,  "6");
    actor->set(BK::GHz2_4,   true);

    actor->setup_actor(HwsimFixture::cfg(), f.base);

    CHECK_NE(iw_info(f.iface).find("channel 6"), string::npos);
}

TEST_CASE("hwsim setup_actor - create sniff iface"){
    HwsimFixture f;
    if(f.skip()) return;

    const string sniff = MONITOR_IFACE_PREFIX + f.iface;
    auto actor = f.make_actor();

    actor->setup_actor(HwsimFixture::cfg("test", {{"sniff_iface", f.iface}}), f.base);

    CHECK(fs::exists("/sys/class/net/" + sniff));

    hw_capabilities::run_cmd({"iw", "dev", sniff, "del"}, nullopt, false);
}
