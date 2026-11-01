#include "attacks/DoS_soft/deauth.h"
#include "page_cache.h"
#include "system/utils.h"
#include "visual/DoS_soft/deauth/deauth_suite.h"
#include "visual/suite_helper.h"
#include <algorithm>
#include <filesystem>

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using visual::deauth_suite::DeauthTestEntry;

void generate_deauth(const path &output_dir, const path &data_dir) {
    const path page_dir = output_dir / "attacks" / "DoS_soft" / "deauth";
    const path base = data_dir / DATA_SUITE / "DoS_soft" / "deauth";
    if(data_unchanged(page_dir, base)) return;

    HtmlGuard f(page_dir);


    f << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deauth DoS (WPA2)</title>
    <link rel="stylesheet" href="../../../style.css">
    <script src="../../../table_aggregate.js"></script>
</head>
<body>
    <a href="../../../index.html" class="back-link"><= Overview</a>
    <h1>Deauthentication DoS Attack (WPA2) - with MFP</h1>

    <div class="card">
        <p><b>Info:</b> hostapd security advisory 2019-7
           (<a href="https://w1.fi/security/2019-7/">w1.fi/security/2019-7</a>) - CVE-2019-16275
		</p>
        <p>The attacker sends a deauthentication frame to the AP where
           SA (source address) == AP's own MAC address <br>
           Unpatched hostapd processes this frame and its response causes connected clients
           to drop association <br>
			- <b>bypassing PMF</b> because the frame targets the AP-side
           state machine, not the client directly.</p>
        <p><b>affected:</b> hostapd 2.10 (without the patch) </p>
        <p><b>success:</b> client disconnected from AP</p>
    </div>
	<div class="card">
		<h2>Mitigations</h2>
		<ul>
			<li> patch added silent ignore of management frames where SA == own_addr </li>
			<li>
				patch: https://w1.fi/security/2019-7/0001-AP-Silently-ignore-management-frame-from-unexpected-.patch
			</li>
		</ul>
	</div>

)html";

    auto emit_table = [&](const string &title, const path &suite_data_dir, const string &t_name) {
        DeauthTestEntry::render_table(f, title, suite_data_dir, page_dir, t_name);
    };

    for(const path &dir : {base / "deauth_filler", base / "deauth_external_client_filler"}) {
        if(!exists(dir)) continue;
        vector<path> subdirs;
        for(const auto &sub : directory_iterator(dir)) {
            if(!sub.is_directory() || !visual::helper::has_test_runs(sub.path())) continue;
            subdirs.push_back(sub.path());
        }
        ranges::sort(subdirs);
        const string base_name = dir.filename().string();
        for(const auto &sub : subdirs) {
            const string sn = sub.filename().string();
            emit_table(base_name + " (" + sn + ")", sub, base_name + " (" + sn + ")");
        }
    }

    f << "</body></html>";
}

}
