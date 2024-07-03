// SPDX-License-Identifier: GPL-2.0-only
#ifndef _BPF_BWQ_H
#define _BPF_BWQ_H

#include <linux/workqueue.h>
#include <linux/percpu.h>
#include <linux/llist.h>
#include <linux/atomic.h>
#include <linux/numa.h>

struct bpf_batched_wq_node {
	struct llist_head queue;
	atomic_t inflight;
};

struct bpf_batched_wq {
	struct bpf_batched_wq_node bwq_nodes[MAX_NUMNODES];
	work_func_t batch_func;
};

void bpf_batched_queue_unbound_work(struct bpf_batched_wq_node *bwq_node,
				    struct work_struct *work,
				    struct llist_node *node);

#define DEFINE_BPF_BATCHED_WQ(name, type, work_memb, work_func, bwq_node,      \
			      llnode)                                          \
	static void bpf_batched_wq_work_func_##name(struct work_struct *w)     \
	{                                                                      \
		type *p = container_of(w, type, work_memb);                    \
		struct llist_node *node, *n;                                   \
                                                                               \
		WARN_ON_ONCE(!atomic_xchg(&p->bwq_node->inflight, 0));         \
		llist_for_each_safe(node, n,                                   \
				    llist_del_all(&p->bwq_node->queue)) {      \
			work_func(                                             \
				&container_of(node, type, llnode)->work_memb); \
			cond_resched();                                        \
		}                                                              \
		work_func(w);                                                  \
	}                                                                      \
	struct bpf_batched_wq name = {                                         \
		.batch_func = bpf_batched_wq_work_func_##name                  \
	};

#endif
