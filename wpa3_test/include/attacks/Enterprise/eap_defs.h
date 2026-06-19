#pragma once
#include <cstdint>

namespace wpa3_tester::eap{
// EAP codes (RFC 3748 §4)
constexpr uint8_t CODE_REQUEST = 1;
constexpr uint8_t CODE_RESPONSE = 2;
constexpr uint8_t CODE_SUCCESS = 3;
constexpr uint8_t CODE_FAILURE = 4;

// EAP type numbers (IANA)
constexpr uint8_t TYPE_IDENTITY = 1;
constexpr uint8_t TYPE_MD5 = 4;
constexpr uint8_t TYPE_GTC = 6;
constexpr uint8_t TYPE_TLS = 13;
constexpr uint8_t TYPE_LEAP = 17;
constexpr uint8_t TYPE_SIM = 18;
constexpr uint8_t TYPE_TTLS = 21;
constexpr uint8_t TYPE_AKA = 23;
constexpr uint8_t TYPE_PEAP = 25;
constexpr uint8_t TYPE_MSCHAPV2 = 26;
constexpr uint8_t TYPE_POTP = 29;
constexpr uint8_t TYPE_FAST = 33;
constexpr uint8_t TYPE_EKE = 40;
constexpr uint8_t TYPE_TEAP = 43;
constexpr uint8_t TYPE_AKA_PRIME = 50;
constexpr uint8_t TYPE_PWD = 52;
constexpr uint8_t TYPE_EXPANDED = 254;

// EAP-PWD opcodes (RFC 5931 §3.1, low 6 bits of Exch byte)
constexpr uint8_t PWD_OPCODE_ID = 1;
constexpr uint8_t PWD_OPCODE_COMMIT = 2;
constexpr uint8_t PWD_OPCODE_CONFIRM = 3;
} 