#pragma once

static const char *AWK_SCRIPT_monitor = R"awk(
BEGIN {
    # Print header so parser knows column layout
    "cat /proc/cpuinfo | grep -c processor" | getline ncores
    close("cat /proc/cpuinfo | grep -c processor")
    printf "# timestamp"
    for (I = 1 I <= ncores I++) printf " cpu%d", I
    print " mem_free_kb airtime_pct rx_drops"
    fflush()

    #print "DEBUG: Monitoring started..." > "/deProcessManager.cppv/stderr"
    while(1) {
        "date +%s" | getline now close("date +%s")
        Out = now

        # CPU staty
        while((getline < "/proc/stat") > 0) {
            if ($1 ~ /^cpu[0-9]+$/) {
                T = $2+$3+$4+$5+$6+$7+$8+$9 Id = $5+$6
                if (Pt[$1] != "") {
                    Dt = T - Pt[$1] Di = Id - Pid[$1]
                    Pct = Dt ? (Dt - Di)*100/Dt : 0
                    Out = Out " " int(Pct)
                }
                Pt[$1] = T Pid[$1] = Id
            }
        } close("/proc/stat")

        # Memory info
        while((getline < "/proc/meminfo") > 0) {
            if ($1 == "MemFree:") { Mem = $2 }
        } close("/proc/meminfo")

        # Network drops
        RxDrops = 0
        while((getline < "/proc/net/dev") > 0) {
            if ($0 ~ iface ":") {
                split($0, a, ":") split(a[2], b, " ") Drops = b[4]
                if (PrevDrops != "") {
                    RxDrops = Drops - PrevDrops
                    if (RxDrops < 0) RxDrops = 0
                }
                PrevDrops = Drops
            }
        } close("/proc/net/dev")

        # WiFi Survey
        Cmd = "iw dev phy0-ap0 survey dump 2>/dev/null"
        Active = 0 Busy = 0 InUse = 0
        while ((Cmd | getline line) > 0) {
            if (line ~ /\[in use\]/) InUse = 1
            if (InUse && line ~ /active time:/)  { split(line, a, ":") split(a[2], b, " ") Active = b[2] }
            if (InUse && line ~ /busy time:/)    { split(line, a, ":") split(a[2], b, " ") Busy   = b[2] InUse = 0 }
        } close(Cmd)

        if (PrevActive != "") {
            Da = Active - PrevActive Db = Busy - PrevBusy
            Airtime = Da ? (Db * 100) / Da : 0
        }
        PrevActive = Active PrevBusy = Busy

        # skip first data row
        if (length(Out) > 15) {
            print Out " " Mem " " int(Airtime) " " RxDrops
            fflush()
        }

        system("sleep " delay)
    }
}
)awk";