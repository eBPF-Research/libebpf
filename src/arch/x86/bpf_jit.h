/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * BPF JIT compiler for ARM64
 *
 * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
 */
#ifndef _BPF_JIT_H
#define _BPF_JIT_H

#include "linux-bpf.h"

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))

#endif /* _BPF_JIT_H */
