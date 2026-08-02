// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include "lib/core.h"
#include "signature.h"

#define SAFEMOD_PROC_NAME "safemod"
#define SAFEMOD_MAX_HITS 32
#define SAFEMOD_SCAN_INSN 64
#define SAFEMOD_ADRP_LOOKAHEAD 8
#define SAFEMOD_STR_MAX 128

#define SAFEMOD_VERDICT_CLEAN 0
#define SAFEMOD_VERDICT_SUSPECT 1
#define SAFEMOD_VERDICT_SUKISU 2
#define SAFEMOD_VERDICT_UNKNOWN 3

#define SAFEMOD_BONUS_STRING_RE 15
#define SAFEMOD_BONUS_STRING 10

static bool safemod_scan = true;
module_param(safemod_scan, bool, 0644);
MODULE_PARM_DESC(safemod_scan, "enable rodata string scan fallback");

struct safemod_hit {
	const char *name;
	unsigned long addr;
	int weight;
	enum safemod_fork fork;
	bool conditional;
	bool str_hit;
};

struct safemod_report {
	int score;
	int hit_count;
	int verdict;
	bool degraded;
	bool string_validated;
	bool scan_skipped;
	char version_string[SAFEMOD_STR_MAX];
	struct safemod_hit hits[SAFEMOD_MAX_HITS];
};

static struct safemod_report safemod_report;

static int safemod_verdict_str(char *buf, size_t size)
{
	static const char *const names[] = {
		"CLEAN", "SUSPECT", "SUKISU", "UNKNOWN",
	};
	return snprintf(buf, size, "%s", names[safemod_report.verdict]);
}

static const char *safemod_fork_name(enum safemod_fork fork)
{
	static const char *const names[] = {
		"Ultra", "ReSukiSU", "shared",
	};
	return names[fork];
}

static void safemod_record_hit(const struct safemod_sig *sig, unsigned long addr)
{
	struct safemod_hit *hit;

	if (safemod_report.hit_count >= SAFEMOD_MAX_HITS) {
		return;
	}
	hit = &safemod_report.hits[safemod_report.hit_count++];
	hit->name = sig->name;
	hit->addr = addr;
	hit->weight = sig->weight;
	hit->fork = sig->fork;
	hit->conditional = sig->conditional;
	hit->str_hit = false;
	safemod_report.score += sig->weight;
}

static void safemod_record_str(const struct safemod_strsig *sig, unsigned long addr)
{
	struct safemod_hit *hit;

	if (safemod_report.hit_count >= SAFEMOD_MAX_HITS) {
		return;
	}
	hit = &safemod_report.hits[safemod_report.hit_count++];
	hit->name = sig->str;
	hit->addr = addr;
	hit->weight = sig->weight;
	hit->fork = sig->fork;
	hit->conditional = false;
	hit->str_hit = true;
	safemod_report.score += sig->weight;
}

static long safemod_sign_extend(unsigned long imm, int bits)
{
	long v = (long)imm;
	if (v & (1L << (bits - 1))) {
		v -= (1L << bits);
	}
	return v;
}

static int safemod_version_validate(unsigned long fn_addr)
{
	u32 code[SAFEMOD_SCAN_INSN];
	unsigned long pc = fn_addr + 4;
	char str[SAFEMOD_STR_MAX];
	int i, j;

	if (safe_read(code, (void *)pc, sizeof(code))) {
		return 0;
	}
	for (i = 0; i < SAFEMOD_SCAN_INSN; i++) {
		u32 adrp = code[i];
		unsigned long imm, page, target;

		if ((adrp & 0x9f000000u) != 0x90000000u) {
			continue;
		}
		imm = (((adrp >> 5) & 0x7ffffu) << 2) | ((adrp >> 29) & 0x3u);
		page = (pc & ~0xffful) + (safemod_sign_extend(imm, 21) << 12);
		for (j = 1; j <= SAFEMOD_ADRP_LOOKAHEAD && i + j < SAFEMOD_SCAN_INSN;
		     j++) {
			u32 add = code[i + j];

			if ((add & 0xff800000u) != 0x91000000u) {
				continue;
			}
			if ((add & 0x1f) != (adrp & 0x1f)) {
				continue;
			}
			target = page + ((add >> 10) & 0xfffu);
			if (safe_read(str, (void *)target, sizeof(str))) {
				continue;
			}
			str[sizeof(str) - 1] = '\0';
			if (strnstr(str, "ReSukiSU", sizeof(str))) {
				strscpy(safemod_report.version_string, str,
					sizeof(safemod_report.version_string));
				safemod_report.string_validated = true;
				return SAFEMOD_FORK_RESUKISU;
			}
			if (str[0] == 'v' && isdigit(str[1]) &&
			    strchr(str, '@')) {
				strscpy(safemod_report.version_string, str,
					sizeof(safemod_report.version_string));
				safemod_report.string_validated = true;
				return -1;
			}
		}
	}
	return 0;
}

static void safemod_string_scan(void)
{
	unsigned long start, end, page;
	char *buf;
	int i;

	if (!safemod_scan) {
		return;
	}
	start = kallsyms_name_to_addr("__start_rodata");
	end = kallsyms_name_to_addr("__end_rodata");
	if (!start || !end || end <= start) {
		safemod_report.scan_skipped = true;
		return;
	}
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		safemod_report.scan_skipped = true;
		return;
	}
	for (page = start; page < end && safemod_report.hit_count < SAFEMOD_MAX_HITS;
	     page += PAGE_SIZE) {
		char *p;

		if (safe_read(buf, (void *)page, PAGE_SIZE)) {
			continue;
		}
		for (i = 0; i < SAFEMOD_STR_COUNT; i++) {
			const struct safemod_strsig *sig = &safemod_str_signatures[i];

			p = memchr(buf, sig->str[0], PAGE_SIZE);
			if (p && strnstr(p, sig->str, PAGE_SIZE - (p - buf))) {
				safemod_record_str(sig, page + (p - buf));
			}
		}
	}
	kfree(buf);
}

static __nocfi void safemod_run_probe(void)
{
	int i;

	for (i = 0; i < SAFEMOD_SIG_COUNT; i++) {
		const struct safemod_sig *sig = &safemod_signatures[i];
		unsigned long addr;

		addr = kallrecon_klp ? kallrecon_klp(sig->name) : 0;
		if (!addr) {
			addr = kallsyms_name_to_addr(sig->name);
		}
		if (!addr) {
			continue;
		}
		safemod_record_hit(sig, addr);
	}

	for (i = 0; i < safemod_report.hit_count; i++) {
		struct safemod_hit *hit = &safemod_report.hits[i];
		int ret;

		if (strcmp(hit->name, "do_get_full_version")) {
			continue;
		}
		ret = safemod_version_validate(hit->addr);
		if (ret == SAFEMOD_FORK_RESUKISU) {
			hit->fork = SAFEMOD_FORK_RESUKISU;
			safemod_report.score += SAFEMOD_BONUS_STRING_RE;
		} else if (ret == -1) {
			safemod_report.score += SAFEMOD_BONUS_STRING;
		}
	}

	if (!safemod_report.hit_count) {
		safemod_string_scan();
	}

	if (safemod_report.score >= 100) {
		safemod_report.verdict = SAFEMOD_VERDICT_SUKISU;
	} else if (safemod_report.score > 0) {
		safemod_report.verdict = SAFEMOD_VERDICT_SUSPECT;
	}
	if (!kallrecon_klp) {
		safemod_report.degraded = true;
	}
}

static enum safemod_fork safemod_dominant_fork(void)
{
	int ultra = 0;
	int re = 0;
	int i;

	for (i = 0; i < safemod_report.hit_count; i++) {
		const struct safemod_hit *hit = &safemod_report.hits[i];

		if (hit->fork == SAFEMOD_FORK_ULTRA) {
			ultra += hit->weight;
		} else if (hit->fork == SAFEMOD_FORK_RESUKISU) {
			re += hit->weight;
		}
	}
	if (re > ultra) {
		return SAFEMOD_FORK_RESUKISU;
	}
	if (ultra > re) {
		return SAFEMOD_FORK_ULTRA;
	}
	return SAFEMOD_FORK_SHARED;
}

static int safemod_proc_show(struct seq_file *m, void *v)
{
	char verdict[16];
	int i;

	safemod_verdict_str(verdict, sizeof(verdict));
	seq_printf(m, "verdict: %s\n", verdict);
	seq_printf(m, "score: %d\n", safemod_report.score);
	if (safemod_report.hit_count) {
		seq_printf(m, "fork: %s\n",
			   safemod_fork_name(safemod_dominant_fork()));
	}
	if (safemod_report.string_validated) {
		seq_printf(m, "version_string: %s\n",
			   safemod_report.version_string);
	}
	if (safemod_report.degraded) {
		seq_puts(m, "degraded: kallsyms_lookup_name unavailable\n");
	}
	if (safemod_report.scan_skipped) {
		seq_puts(m, "string_scan: skipped, rodata bounds unavailable\n");
	}
	for (i = 0; i < safemod_report.hit_count; i++) {
		const struct safemod_hit *hit = &safemod_report.hits[i];

		seq_printf(m, "hit: %-40s %3d %-8s %lx%s%s\n", hit->name,
			   hit->weight, safemod_fork_name(hit->fork), hit->addr,
			   hit->conditional ? " [conditional]" : "",
			   hit->str_hit ? " [string]" : "");
	}
	return 0;
}

static int safemod_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, safemod_proc_show, NULL);
}

static const struct proc_ops safemod_proc_fops = {
	.proc_open = safemod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init safemod_init(void)
{
	char verdict[16];

	find_kallsyms_base();
	if (klnum_val) {
		safemod_run_probe();
	} else {
		safemod_report.degraded = true;
		safemod_report.verdict = SAFEMOD_VERDICT_UNKNOWN;
	}
	proc_create(SAFEMOD_PROC_NAME, 0444, NULL, &safemod_proc_fops);
	safemod_verdict_str(verdict, sizeof(verdict));
	pr_info("safemod: verdict %s score %d hits %d\n", verdict,
		safemod_report.score, safemod_report.hit_count);
	return 0;
}

static void __exit safemod_exit(void)
{
	remove_proc_entry(SAFEMOD_PROC_NAME, NULL);
}

module_init(safemod_init);
module_exit(safemod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dere3046");
MODULE_DESCRIPTION("sukisu presence detector");
