#!/system/bin/sh

MODDIR=${0%/*}
AUDIT="$MODDIR/audit.log"
DETECT="$MODDIR/lib/arm64-v8a/safemod-user.sh"

rm -f "$AUDIT"
"$DETECT" > "$AUDIT" 2>&1
