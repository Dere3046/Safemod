// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <linux/types.h>

enum safemod_fork {
	SAFEMOD_FORK_ULTRA,
	SAFEMOD_FORK_RESUKISU,
	SAFEMOD_FORK_SHARED,
};

struct safemod_sig {
	const char *name;
	int weight;
	enum safemod_fork fork;
	bool conditional;
};

static const struct safemod_sig safemod_signatures[] = {
	/* Ultra, unconditional */
	{ "ksu_spoof_version", 100, SAFEMOD_FORK_ULTRA, false },
	{ "ksu_set_spoof_version", 90, SAFEMOD_FORK_ULTRA, false },
	{ "do_spoof_version", 80, SAFEMOD_FORK_ULTRA, false },
	{ "do_set_spoof_version", 80, SAFEMOD_FORK_ULTRA, false },
	{ "list_try_umount", 75, SAFEMOD_FORK_ULTRA, false },
	/* Ultra, CONFIG_KPM only */
	{ "sukisu_kpm_load_module_path", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_kpm_unload_module", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_kpm_num", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_kpm_info", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_kpm_list", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_kpm_control", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_kpm_version", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_handle_kpm", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_compact_find_symbol", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_super_find_struct", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_super_access", 100, SAFEMOD_FORK_ULTRA, true },
	{ "sukisu_super_container_of", 100, SAFEMOD_FORK_ULTRA, true },
	{ "do_enable_kpm", 75, SAFEMOD_FORK_ULTRA, true },
	/* ReSukiSU, unconditional */
	{ "ksu_handle_dynamic_manager", 100, SAFEMOD_FORK_RESUKISU, false },
	{ "ksu_start_apatch_conflict_check", 90, SAFEMOD_FORK_RESUKISU, false },
	{ "do_get_kernel_patch_implement", 85, SAFEMOD_FORK_RESUKISU, false },
	{ "do_dynamic_manager", 80, SAFEMOD_FORK_RESUKISU, false },
	{ "do_get_managers", 80, SAFEMOD_FORK_RESUKISU, false },
	{ "detect_conflict_thread", 75, SAFEMOD_FORK_RESUKISU, false },
	{ "kernel_patch_type", 70, SAFEMOD_FORK_RESUKISU, false },
	/* ReSukiSU, CONFIG_KSU_TOOLKIT_SUPPORT only */
	{ "ksu_try_handle_toolkit_cmd", 80, SAFEMOD_FORK_RESUKISU, true },
	{ "ksuver_override", 40, SAFEMOD_FORK_RESUKISU, true },
	{ "ksuflags_override", 40, SAFEMOD_FORK_RESUKISU, true },
	/* shared, both forks, absent in upstream */
	{ "do_get_full_version", 80, SAFEMOD_FORK_SHARED, false },
	{ "do_get_hook_type", 80, SAFEMOD_FORK_SHARED, false },
};

#define SAFEMOD_SIG_COUNT ARRAY_SIZE(safemod_signatures)

#endif
