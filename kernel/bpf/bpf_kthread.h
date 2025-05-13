/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Isovalent */
#ifndef __BPF_KTHREAD_H
#define __BPF_KTHREAD_H

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/hrtimer.h>

int bpf_kthread_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int bpf_kthread_prog_detach(const union bpf_attr *attr, struct bpf_prog *prog);

void bpf_kthread_program_run(struct work_struct *work);
enum hrtimer_restart bpf_kthread_timer_callback(struct hrtimer *timer);

#endif /* __BPF_KTHREAD_H */
