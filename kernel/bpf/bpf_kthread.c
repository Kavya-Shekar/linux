// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 Facebook
 */
#include <linux/bpf.h>
#include <linux/printk.h>
#include <linux/workqueue.h>
#include <linux/workqueue_types.h>
#include <linux/hrtimer.h>
#include <linux/filter.h>

#include "bpf_kthread.h"

static struct workqueue_struct *bpf_kthread_wq;

/* Work function for schedulable BPF programs */
void bpf_kthread_program_run(struct work_struct *work)
{
	struct bpf_prog *prog = container_of(work, struct bpf_prog, sched_work);
	unsigned long dummy_ctx = 0;
	int ret = bpf_prog_run(prog, &dummy_ctx);

	/* Handle the return value if necessary */
	if (ret != 0) {
		pr_warn("BPF program %d failed, returned non-zero value %d\n",
			prog->aux->id, ret);
	}

	/* Reschedule the timer*/
	hrtimer_start(&prog->sched_timer, ktime_set(0, 100000000), HRTIMER_MODE_REL);
}

enum hrtimer_restart bpf_kthread_timer_callback(struct hrtimer *timer)
{
	struct bpf_prog *prog = container_of(timer, struct bpf_prog, sched_timer);

	// Work is already pending, do not queue it again.
	if (work_pending(&prog->sched_work))
		return HRTIMER_NORESTART;

	queue_work(bpf_kthread_wq, &prog->sched_work);

	/* The timer is restarted in the work function for periodic jobs */
	return HRTIMER_NORESTART;
}

int bpf_kthread_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	if(!bpf_kthread_wq) {
		pr_info("Init BPF workqueue\n");
		bpf_kthread_wq = alloc_workqueue("bpf_sched_wq", 0, 0);
		if (!bpf_kthread_wq) {
			pr_err("Failed to create bpf_sched_wq\n");
			return -ENOMEM;
		}
	}

	hrtimer_init(&prog->sched_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	prog->sched_timer.function = bpf_kthread_timer_callback;
	hrtimer_start(&prog->sched_timer, ktime_set(0, 100000000), HRTIMER_MODE_REL);

	INIT_WORK(&prog->sched_work, bpf_kthread_program_run);

	return 0;
}

int bpf_kthread_prog_detach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	/* Stop timer to stop periodic schedule */
	hrtimer_cancel(&prog->sched_timer);

	/* Stop any running work_struct */
	cancel_work_sync(&prog->sched_work);

	/* Clean up program reference */
	bpf_prog_put(prog);

	return 0;
}
