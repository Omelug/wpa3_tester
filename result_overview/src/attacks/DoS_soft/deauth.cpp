#include "attacks/DoS_soft/deauth.h"
#include "page_cache.h"
#include "system/utils.h"
#include "visual/DoS_soft/deauth/deauth_suite.h"
#include <filesystem>

namespace wpa3_tester::overview {
using namespace std;
using namespace filesystem;
using visual::deauth_suite::DeauthTestEntry;

void generate_deauth(const path &output_dir, const path &data_dir) {
    const path page_dir = output_dir / "attacks" / "DoS_soft" / "deauth";
    if(data_unchanged(page_dir, data_dir)) return;

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

    const path base = data_dir / DATA_SUITE / "DoS_soft" / "deauth";
    emit_table("WPA2 deauth filler (2.9, 2.10)",
        base / "deauth_filler", "deauth_filler");

    f << "</body></html>";
    update_data_stamp(page_dir, data_dir);
}

}
