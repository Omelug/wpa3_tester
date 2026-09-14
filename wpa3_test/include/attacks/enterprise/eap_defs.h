#pragma once
#include <cstdint>

namespace wpa3_tester::eap {

// EAP codes (RFC 3748 §4)
enum EapCode : uint8_t {
    CODE_REQUEST = 1,
    CODE_RESPONSE = 2,
    CODE_SUCCESS = 3,
    CODE_FAILURE = 4,
};

// EAP type numbers (IANA)
enum EapType : uint8_t {
    TYPE_IDENTITY  = 1,
    TYPE_MD5       = 4,
    TYPE_GTC       = 6,
    TYPE_TLS       = 13,
    TYPE_LEAP      = 17,
    TYPE_SIM       = 18,
    TYPE_TTLS      = 21,
    TYPE_AKA       = 23,
    TYPE_PEAP      = 25,
    TYPE_MSCHAPV2  = 26,
    TYPE_POTP      = 29,
    TYPE_FAST      = 33,
    TYPE_EKE       = 40,
    TYPE_TEAP      = 43,
    TYPE_AKA_PRIME = 50,
    TYPE_PWD       = 52,
    TYPE_EXPANDED  = 254,
};

// EAP-PWD opcodes (RFC 5931 §3.1, PWD-Exch)
enum PwdOpcode : uint8_t {
    PWD_OPCODE_ID      = 1,
    PWD_OPCODE_COMMIT  = 2,
    PWD_OPCODE_CONFIRM = 3,
};

}