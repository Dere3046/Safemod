#!/system/bin/sh

MODDIR=${0%/*}
AUDIT="$MODDIR/audit.log"
LKM="$MODDIR/lib/arm64-v8a/lkm"

sdk=$(getprop ro.build.version.sdk)
krel=$(uname -r)
pair=$(echo "$krel" | cut -d. -f1-2)

case "$sdk:$pair" in
31:5.10|32:5.10) ko="$LKM/safemod-android12-5.10.ko" ;;
33:5.10) ko="$LKM/safemod-android13-5.10.ko" ;;
33:5.15) ko="$LKM/safemod-android13-5.15.ko" ;;
34:5.15) ko="$LKM/safemod-android14-5.15.ko" ;;
34:6.1) ko="$LKM/safemod-android14-6.1.ko" ;;
35:6.6) ko="$LKM/safemod-android15-6.6.ko" ;;
36:6.12) ko="$LKM/safemod-android16-6.12.ko" ;;
*)
    echo "no matching lkm for sdk $sdk kernel $pair"
    exit 1
    ;;
esac

[ -f "$ko" ] || { echo "lkm missing: $ko"; exit 1; }

rmmod safemod 2>/dev/null
insmod "$ko" 2>/dev/null || { echo "insmod failed: $ko"; exit 1; }
result=$(cat /proc/safemod 2>/dev/null)
rmmod safemod 2>/dev/null

{
    echo "==== $(date '+%F %T') kernel $krel ===="
    echo "$result"
} >> "$AUDIT"
echo "$result"
