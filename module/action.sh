#!/system/bin/sh

MODDIR=${0%/*}
AUDIT="$MODDIR/audit.log"
LKM="$MODDIR/lib/arm64-v8a/lkm"

. "$MODDIR/lib/arm64-v8a/status.sh"

krel=$(uname -r)
pair=$(echo "$krel" | cut -d. -f1-2)
android=$(echo "$krel" | sed -n 's/.*-android\([0-9]*\)-.*/\1/p')

case "$android:$pair" in
12:5.10) ko="$LKM/safemod-android12-5.10.ko" ;;
13:5.10) ko="$LKM/safemod-android13-5.10.ko" ;;
13:5.15) ko="$LKM/safemod-android13-5.15.ko" ;;
14:5.15) ko="$LKM/safemod-android14-5.15.ko" ;;
14:6.1) ko="$LKM/safemod-android14-6.1.ko" ;;
15:6.6) ko="$LKM/safemod-android15-6.6.ko" ;;
16:6.12) ko="$LKM/safemod-android16-6.12.ko" ;;
*)
    echo "no matching lkm for kernel $krel"
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

ker=$(echo "$result" | sed -n 's/^verdict: //p' | tr '[:upper:]' '[:lower:]')
user=""
[ -f "$STATUS" ] && . "$STATUS"
echo "user=$user" > "$STATUS"
echo "ker=$ker" >> "$STATUS"
safemod_refresh_desc
echo "$result"
