#pragma once
namespace wpa3_tester::test_monitor_bl0ck{

    void speed_observation_start(RunStatus &rs);
    //void setup_attack(RunStatus& rs);
    void run_attack(RunStatus& rs);
    void stats_attack(const RunStatus& rs);
}
