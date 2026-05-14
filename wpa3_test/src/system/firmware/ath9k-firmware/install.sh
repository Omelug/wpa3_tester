#!/usr/bin/env bash

# 1. Source files (your modified ones)
LOCAL_7010="htc_7010.fw"
LOCAL_9271="htc_9271.fw"

# 2. Detect the base firmware directory
if [ -d "/run/current-system/firmware" ]; then
    FW_BASE="/run/current-system/firmware"  # NixOS path
elif [ -d "/lib/firmware" ]; then
    FW_BASE="/lib/firmware"                # Debian/Standard path
else
    echo "[-] Error: Could not find firmware directory."
    exit 1
fi

apply_test_fw() {
    local SOURCE=$1
    local SEARCH=$2

    # Find the specific file (handling potential .zst extension)
    local TARGET=$(find "$FW_BASE/ath9k_htc/" -name "$SEARCH" | head -n 1)

    if [ -z "$TARGET" ]; then
        echo "[-] Target for $SEARCH not found in $FW_BASE"
        return
    fi

    echo "[+] Found Target: $TARGET"

    # If the system uses compression, we must match it
    if [[ "$TARGET" == *.zst ]]; then
        echo "[!] Compressing source to .zst for NixOS compatibility..."
        zstd -f -k "$SOURCE" -o "${SOURCE}.zst"
        SOURCE="${SOURCE}.zst"
    fi

    # Bind mount over the target
    echo "[+] Mounting $SOURCE over $TARGET"
    sudo mount --bind "$SOURCE" "$TARGET"
}

# Apply for both chips
apply_test_fw "$LOCAL_7010" "*7010*"
apply_test_fw "$LOCAL_9271" "*9271*"

# 3. Reload the driver
echo "[+] Reloading driver..."
sudo modprobe -r ath9k_htc && sudo modprobe ath9k_htc

echo "[+] Done. If no change appears in dmesg, please physically replug the USB device."