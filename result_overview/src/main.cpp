#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#include "attacks/DoS_soft/bl0ck.h"
#include "attacks/DoS_soft/channel_switch.h"
#include "system/utils.h"

using namespace std;
using namespace filesystem;

static path project_root() {
    char buf[4096]{};
    const ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) return current_path();
    return path(buf).parent_path().parent_path().parent_path();
}

static string html_page() {
    ostringstream out;
    out << R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WPA3 Tester — Results Overview</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <h1>WPA3 Tester — Results Overview</h1>

    <div class="card">
        <h2>Attack Categories</h2>
        <ul>
            <li><a href="attacks/dos_soft/channel_switch/index.html">DoS Soft — Channel Switch (CSA)</a></li>
            <li><a href="attacks/dos_soft/bl0ck/index.html">DoS Soft — Block ACK (Bl0ck)</a></li>

        </ul>
    </div>

)html";
	//FIXME TODO  add link to devices
    out << R"html(    </div>

</body>
</html>
)html";
    return out.str();
}

int main() {
    const path root        = project_root();
    const path output_dir  = root / "build" / "result_overview";
    const path data_dir    = root / "data";
    const path attacks_dir = root / "wpa3_test" / "src" / "attacks";

    wpa3_tester::create_public_dirs(output_dir);

    const path index = output_dir / "index.html";
    ofstream f(index);
    f << html_page();
    f.close();
    wpa3_tester::set_public_perms(index);

    wpa3_tester::overview::generate_channel_switch(output_dir, data_dir);
    wpa3_tester::overview::generate_bl0ck(output_dir, data_dir);

    return 0;
}
