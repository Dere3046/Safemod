#!/system/bin/sh

KALLSYMS=/proc/kallsyms

score=0
ultra_score=0
re_score=0
hits=""

sigs="\
ksu_spoof_version:100:Ultra
ksu_set_spoof_version:90:Ultra
do_spoof_version:80:Ultra
do_set_spoof_version:80:Ultra
list_try_umount:75:Ultra
sukisu_kpm_load_module_path:100:Ultra
sukisu_kpm_unload_module:100:Ultra
sukisu_kpm_num:100:Ultra
sukisu_kpm_info:100:Ultra
sukisu_kpm_list:100:Ultra
sukisu_kpm_control:100:Ultra
sukisu_kpm_version:100:Ultra
sukisu_handle_kpm:100:Ultra
sukisu_compact_find_symbol:100:Ultra
sukisu_super_find_struct:100:Ultra
sukisu_super_access:100:Ultra
sukisu_super_container_of:100:Ultra
do_enable_kpm:75:Ultra
ksu_handle_dynamic_manager:100:ReSukiSU
ksu_start_apatch_conflict_check:90:ReSukiSU
do_get_kernel_patch_implement:85:ReSukiSU
do_dynamic_manager:80:ReSukiSU
do_get_managers:80:ReSukiSU
detect_conflict_thread:75:ReSukiSU
kernel_patch_type:70:ReSukiSU
ksu_try_handle_toolkit_cmd:80:ReSukiSU
ksuver_override:40:ReSukiSU
ksuflags_override:40:ReSukiSU
do_get_full_version:80:shared
do_get_hook_type:80:shared"

[ -r "$KALLSYMS" ] || {
    echo "verdict: UNKNOWN"
    echo "degraded: /proc/kallsyms unreadable"
    exit 0
}

names=$(awk '{print $3}' "$KALLSYMS")

module_present=0
echo "$names" | grep -qx "kernelsu_init" && module_present=1
if [ "$module_present" -eq 0 ]; then
    echo "$names" | grep -qx "ksu_cred" && module_present=1
fi

for sig in $sigs; do
    name=${sig%%:*}
    rest=${sig#*:}
    weight=${rest%%:*}
    fork=${rest#*:}

    if echo "$names" | grep -qx "$name"; then
        score=$((score + weight))
        if [ "$fork" = Ultra ]; then
            ultra_score=$((ultra_score + weight))
        elif [ "$fork" = ReSukiSU ]; then
            re_score=$((re_score + weight))
        fi
        hits="$hits
hit: $name $weight $fork"
    fi
done

if [ "$score" -ge 100 ]; then
    verdict=SUKISU
elif [ "$score" -gt 0 ]; then
    verdict=SUSPECT
else
    verdict=CLEAN
fi

echo "verdict: $verdict"
echo "score: $score"
if [ "$module_present" -eq 1 ]; then
    echo "module: kernelsu present"
fi
if [ "$re_score" -gt "$ultra_score" ]; then
    echo "fork: ReSukiSU"
elif [ "$ultra_score" -gt "$re_score" ]; then
    echo "fork: Ultra"
elif [ "$score" -gt 0 ]; then
    echo "fork: shared"
fi
[ -n "$hits" ] && echo "$hits"
exit 0
