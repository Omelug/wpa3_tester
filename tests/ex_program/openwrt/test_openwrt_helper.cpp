#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest.h>
#include <filesystem>
#include <fstream>

#include "ex_program/external_actors/openwrt/openwrt_helper.h"
#include "logger/log.h"

using namespace std;
using namespace filesystem;
using namespace wpa3_tester;

// ------- akm_from_openwrt_log

static void write_sae_associated_log(const path &p){
	ofstream f(p);
	f << "2026-07-26T23:10:00.369083810+0200 [ap] [stdout] Add associated STA f0:a6:54:d0:ff:ed (added_unassoc=1 auth_alg=3 ft_over_ds=0 reassoc=0 authorized=0 ft_tk=0 fils_tk=0)\n";
}

static void write_two_client_associated_log(const path &p){
	ofstream f(p);
	f << "2026-07-26T23:10:00.369083810+0200 [ap] [stdout] Add associated STA f0:a6:54:d0:ff:ed (added_unassoc=1 auth_alg=3 ft_over_ds=0 reassoc=0 authorized=0 ft_tk=0 fils_tk=0)\n"
	  << "2026-07-26T23:10:05.112233445+0200 [ap] [stdout] Add associated STA 9c:b6:d0:12:34:56 (added_unassoc=1 auth_alg=0 ft_over_ds=0 reassoc=0 authorized=0 ft_tk=0 fils_tk=0)\n";
}

TEST_CASE("akm_from_openwrt_log - returns SAE classified as WPA3"){
	const path tmp = temp_directory_path() / "openwrt_test_akm_sae.log";
	write_sae_associated_log(tmp);

	const string akm = openwrt::akm_from_openwrt_log(tmp, {});
	remove(tmp);

	CHECK_EQ(akm, "SAE\n(WPA3)");
}

TEST_CASE("akm_from_openwrt_log - returns raw algorithm name for non-SAE auth_alg"){
	const path tmp = temp_directory_path() / "openwrt_test_akm_open.log";
	{
		ofstream f(tmp);
		f << "2026-07-26T23:10:05.112233445+0200 [ap] [stdout] Add associated STA 9c:b6:d0:12:34:56 (added_unassoc=1 auth_alg=0 ft_over_ds=0 reassoc=0 authorized=0 ft_tk=0 fils_tk=0)\n";
	}
	const string akm = openwrt::akm_from_openwrt_log(tmp, {});
	remove(tmp);

	// auth_alg=0 (Open System) doesn't by itself imply WPA2 or WPA3 - actual
	// key management (e.g. PSK) is negotiated later in the 4-way handshake.
	CHECK_EQ(akm, "Open System");
}

TEST_CASE("akm_from_openwrt_log - MAC filter picks the right STA's auth_alg"){
	const path tmp = temp_directory_path() / "openwrt_test_akm_mac_filter.log";
	write_two_client_associated_log(tmp);

	CHECK_EQ(openwrt::akm_from_openwrt_log(tmp, "f0:a6:54:d0:ff:ed"), "SAE\n(WPA3)");
	CHECK_EQ(openwrt::akm_from_openwrt_log(tmp, "9c:b6:d0:12:34:56"), "Open System");
	CHECK_EQ(openwrt::akm_from_openwrt_log(tmp, "aa:bb:cc:dd:ee:ff"), "");

	remove(tmp);
}

TEST_CASE("akm_from_openwrt_log - ignores a malformed auth_alg value"){
	const path tmp = temp_directory_path() / "openwrt_test_akm_malformed.log";
	{
		ofstream f(tmp);
		f << "2026-07-26T23:10:00.369083810+0200 [ap] [stdout] Add associated STA f0:a6:54:d0:ff:ed (added_assoc=1 auth_alg=not_a_number ft_over_ds=0)\n"
		  << "2026-07-26T23:10:05.112233445+0200 [ap] [stdout] Add associated STA 9c:b6:d0:12:34:56 (added_unassoc=1 auth_alg=0 ft_over_ds=0)\n";
	}
	const string akm = openwrt::akm_from_openwrt_log(tmp, {});
	remove(tmp);

	// The first line's auth_alg isn't numeric and is skipped entirely,
	// rather than crashing or being misreported - the next valid line wins.
	CHECK_EQ(akm, "Open System");
}

TEST_CASE("akm_from_openwrt_log - returns empty when no Add associated STA line is present"){
	const path tmp = temp_directory_path() / "openwrt_test_akm_missing.log";
	{
		ofstream f(tmp);
		f << "2026-07-26T23:10:00.334468049+0200 [ap] [stdout] authentication: STA=f0:a6:54:d0:ff:ed auth_alg=3 auth_transaction=1 status_code=0 wep=0 seq_ctrl=0x410\n"
		  << "2026-07-26T23:10:00.425366187+0200 [ap] [stdout] wlan2: AP-STA-CONNECTED f0:a6:54:d0:ff:ed\n";
	}
	const string akm = openwrt::akm_from_openwrt_log(tmp, {});
	remove(tmp);

	CHECK_EQ(akm, "");
}

TEST_CASE("akm_from_openwrt_log - returns empty for missing file"){
	CHECK_EQ(openwrt::akm_from_openwrt_log("/tmp/openwrt_nonexistent_akm.log", {}), "");
}

TEST_CASE("akm_from_openwrt_log - only reads lines before window.start_tp"){
	const path tmp = temp_directory_path() / "openwrt_test_akm_window.log";
	{
		ofstream f(tmp);
		f << "2026-07-26T23:10:00.000000000+0200 [ap] [stdout] some earlier line, no associated STA here\n"
		  << "2026-07-26T23:10:05.000000000+0200 [ap] [stdout] Add associated STA f0:a6:54:d0:ff:ed (added_unassoc=1 auth_alg=3)\n";
	}
	const TimeWindow window{log_time_to_epoch_ns("2026-07-26T23:10:02.000000000+0200"), {}};
	const string akm = openwrt::akm_from_openwrt_log(tmp, {}, window);
	remove(tmp);

	// The "Add associated STA" line's own timestamp (23:10:05) is at/after
	// window.start_tp (23:10:02), so it's never read.
	CHECK_EQ(akm, "");
}

// ------- mfp_from_openwrt_log

TEST_CASE("mfp_from_openwrt_log - returns REQUIRED for an SAE-associated STA"){
	const path tmp = temp_directory_path() / "openwrt_test_mfp_sae.log";
	write_sae_associated_log(tmp);

	const string mfp = openwrt::mfp_from_openwrt_log(tmp, {});
	remove(tmp);

	CHECK_EQ(mfp, "REQUIRED");
}

TEST_CASE("mfp_from_openwrt_log - returns empty for a non-SAE-associated STA"){
	const path tmp = temp_directory_path() / "openwrt_test_mfp_open.log";
	{
		ofstream f(tmp);
		f << "2026-07-26T23:10:05.112233445+0200 [ap] [stdout] Add associated STA 9c:b6:d0:12:34:56 (added_unassoc=1 auth_alg=0 ft_over_ds=0 reassoc=0 authorized=0 ft_tk=0 fils_tk=0)\n";
	}
	const string mfp = openwrt::mfp_from_openwrt_log(tmp, {});
	remove(tmp);

	CHECK_EQ(mfp, "");
}

TEST_CASE("mfp_from_openwrt_log - MAC filter picks the right STA's result"){
	const path tmp = temp_directory_path() / "openwrt_test_mfp_mac_filter.log";
	write_two_client_associated_log(tmp);

	CHECK_EQ(openwrt::mfp_from_openwrt_log(tmp, "f0:a6:54:d0:ff:ed"), "REQUIRED");
	CHECK_EQ(openwrt::mfp_from_openwrt_log(tmp, "9c:b6:d0:12:34:56"), "");
	CHECK_EQ(openwrt::mfp_from_openwrt_log(tmp, "aa:bb:cc:dd:ee:ff"), "");

	remove(tmp);
}

TEST_CASE("mfp_from_openwrt_log - returns empty when no Add associated STA line is present"){
	const path tmp = temp_directory_path() / "openwrt_test_mfp_missing.log";
	{
		ofstream f(tmp);
		f << "2026-07-26T23:10:00.425366187+0200 [ap] [stdout] wlan2: AP-STA-CONNECTED f0:a6:54:d0:ff:ed\n";
	}
	const string mfp = openwrt::mfp_from_openwrt_log(tmp, {});
	remove(tmp);

	CHECK_EQ(mfp, "");
}

TEST_CASE("mfp_from_openwrt_log - returns empty for missing file"){
	CHECK_EQ(openwrt::mfp_from_openwrt_log("/tmp/openwrt_nonexistent_mfp.log", {}), "");
}

TEST_CASE("mfp_from_openwrt_log - only reads lines before window.start_tp"){
	const path tmp = temp_directory_path() / "openwrt_test_mfp_window.log";
	{
		ofstream f(tmp);
		f << "2026-07-26T23:10:00.000000000+0200 [ap] [stdout] some earlier line, no associated STA here\n"
		  << "2026-07-26T23:10:05.000000000+0200 [ap] [stdout] Add associated STA f0:a6:54:d0:ff:ed (added_unassoc=1 auth_alg=3)\n";
	}
	const TimeWindow window{log_time_to_epoch_ns("2026-07-26T23:10:02.000000000+0200"), {}};
	const string mfp = openwrt::mfp_from_openwrt_log(tmp, {}, window);
	remove(tmp);

	CHECK_EQ(mfp, "");
}