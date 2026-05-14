#!/usr/bin/env bash

# 1. Identify the firmware base
if [ -d "/run/current-system/firmware" ]; then
    FW_ROOT="/run/current-system/firmware"
elif [ -d "/lib/firmware" ]; then
    FW_ROOT="/lib/firmware"
else
    echo "[-] Error: Could not find system firmware directory."
    exit 1
fi

echo "[+] Starting cleanup of modified firmware..."

# 2. Unload the driver first to prevent crashes
echo "[+] Unloading ath9k_htc driver..."
sudo modprobe -r ath9k_htc

# 3. Find and Unmount all bind mounts in the firmware directory
# We look specifically for mounts active in our target folder
MOUNTS=$(mount | grep "$FW_ROOT/ath9k_htc" | awk '{print $3}')

if [ -z "$MOUNTS" ]; then
    echo "[!] No active firmware mounts found. System is already using original files."
else
    for MNT in $MOUNTS; do
        echo "[+] Unmounting: $MNT"
        sudo umount "$MNT"
    done
fi

# 4. Reload the driver (it will now load the ORIGINAL firmware)
echo "[+] Reloading driver (original firmware)..."
sudo modprobe ath9k_htc

# 5. Verification
echo "[+] Verification:"
# Check dmesg for the "Transferred FW" size of the original file
dmesg | tail -n 20 | grep ath9k

echo "[+] Cleanup complete. Your system is back to its original state."