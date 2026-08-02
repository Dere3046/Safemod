#!/system/bin/sh

chmod 755 "$MODPATH/lib/arm64-v8a/safemod-user.sh"

case "$ARCH" in
arm64) ;;
*)
    rm -rf "$MODPATH/lib/arm64-v8a/lkm"
    ;;
esac
