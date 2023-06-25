/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Just-In-Time compiler for BPF filters on 32bit ARM
 *
 * Copyright (c) 2011 Mircea Gherzan <mgherzan@gmail.com>
 */

#ifndef PFILTER_OPCODES_ARM_H
#define PFILTER_OPCODES_ARM_H

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT		12
#define PAGE_SIZE		((1UL) << PAGE_SHIFT)
#define PAGE_MASK		(~((1 << PAGE_SHIFT) - 1))

// #define CONFIG_FRAME_POINTER 1
#define __LINUX_ARM_ARCH__ 7
#define HWCAP_IDIVA 0

#endif /* PFILTER_OPCODES_ARM_H */
