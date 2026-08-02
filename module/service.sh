#!/system/bin/sh

MODDIR=${0%/*}
AUDIT="$MODDIR/audit.log"
DETECT="$MODDIR/lib/arm64-v8a/safemod-user.sh"

. "$MODDIR/lib/arm64-v8a/status.sh"

rm -f "$AUDIT"
rm -f "$STATUS"
safemod_clean_desc

"$DETECT" > "$AUDIT" 2>&1
user=$(sed -n 's/^verdict: //p' "$AUDIT" | tr '[:upper:]' '[:lower:]')
[ -n "$user" ] && echo "user=$user" > "$STATUS"
safemod_refresh_desc
