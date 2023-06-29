// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
// #include "../../extensions/vmlinux/vmlinux.h"

#define TASK_COMM_LEN 16

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif;

struct task_struct {
	char comm[TASK_COMM_LEN];
	int pid;
};
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

const volatile unsigned long long min_duration_ns = 0;
static unsigned long long (*bpf_get_current_task)(void) = (void *) 35;

int handle_exec(void *ctx)
{
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task();

	// ppid = BPF_CORE_READ(task, real_parent, tgid);
	return task->pid;
}
