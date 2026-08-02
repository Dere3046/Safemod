#!/system/bin/sh

# status helpers, sourced by service.sh and action.sh

PROP="$MODDIR/module.prop"
STATUS="$MODDIR/status.prop"

safemod_clean_desc()
{
    sed -i 's/ *\[[^]]*\] *//g' "$PROP"
}

safemod_refresh_desc()
{
    user=""
    ker=""
    tag=""

    [ -f "$STATUS" ] && . "$STATUS"
    [ -n "$user" ] && tag="${tag}user:${user},"
    [ -n "$ker" ] && tag="${tag}Ker:${ker},"
    tag=${tag%,}
    safemod_clean_desc
    if [ -n "$tag" ]; then
        sed -i "s/^description=.*/& [$tag]/" "$PROP"
    fi
}
