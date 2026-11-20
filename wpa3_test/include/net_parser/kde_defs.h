#pragma once
#include <cstdint>
#include <cstddef>
#include <map>
#include <string_view>

// Key Data Encapsulation (KDE) - IEEE 802.11-2024, Section 12.7.2
// Wire format (Figure 12-37):  Type(1) | Length(1) | OUI(3) | DataType(1) | Data(Length-4)

namespace wpa3_tester::kde {

constexpr uint8_t  KDE_TYPE     = 0xDD; // same as IE_VENDOR_SPECIFIC; see NOTE 10 in §12.7.2
constexpr uint8_t  IEEE_OUI[3]  = {0x00, 0x0F, 0xAC};
// KDE header = Type(1) + Length(1) + OUI(3) + DataType(1)
constexpr size_t   KDE_HDR_SIZE = 6;
// Length field value = OUI(3) + DataType(1) + Data - i.e. total_kde_size - 2
constexpr size_t   KDE_LEN_OVERHEAD = 4; // bytes accounted for by Length field: OUI+DataType+Data

// KDE Data Type selectors - IEEE 802.11-2024, Table 12-10
// OUI = 00-0F-AC for all entries below; "Other OUI or CID / Any" = vendor specific
enum KdeSel : uint8_t {
    KDE_GTK             =  1,
    KDE_MAC_ADDR        =  3,
    KDE_PMKID           =  4,
    KDE_NONCE           =  6,
    KDE_LIFETIME        =  7,
    KDE_ERROR           =  8,
    KDE_IGTK            =  9,
    KDE_KEY_ID          = 10,
    KDE_MULTIBAND_GTK   = 11,
    KDE_MULTIBAND_KEY_ID= 12,
    KDE_OCI             = 13,
    KDE_BIGTK           = 14,
    KDE_WIGTK           = 15,
};

// PMKID KDE data size - Figure 12-40: single 16-octet PMKID field
constexpr size_t PMKID_SIZE     = 16;
// Full PMKID KDE wire size: KDE_HDR_SIZE + PMKID_SIZE
constexpr size_t PMKID_KDE_SIZE = KDE_HDR_SIZE + PMKID_SIZE; // = 22
// Length field value for PMKID KDE: OUI(3) + DataType(1) + Data(16) = 20
constexpr uint8_t PMKID_KDE_LEN = static_cast<uint8_t>(KDE_LEN_OVERHEAD + PMKID_SIZE); // = 20

inline const std::map<KdeSel, std::string_view> kde_names = {
    {KDE_GTK,              "GTK"},
    {KDE_MAC_ADDR,         "MAC-Addr"},
    {KDE_PMKID,            "PMKID"},
    {KDE_NONCE,            "Nonce"},
    {KDE_LIFETIME,         "Lifetime"},
    {KDE_ERROR,            "Error"},
    {KDE_IGTK,             "IGTK"},
    {KDE_KEY_ID,           "KeyID"},
    {KDE_MULTIBAND_GTK,    "Multiband-GTK"},
    {KDE_MULTIBAND_KEY_ID, "Multiband-KeyID"},
    {KDE_OCI,              "OCI"},
    {KDE_BIGTK,            "BIGTK"},
    {KDE_WIGTK,            "WIGTK"},
};

inline std::string_view to_string(KdeSel v) {
    const auto it = kde_names.find(v);
    return it != kde_names.end() ? it->second : "<unknown KDE>";
}

}
