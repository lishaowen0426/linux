#ifndef _LINUX_BPF_NAMESPACE_H
#define _LINUX_BPF_NAMESPACE_H

#include "linux/compiler_types.h"
#include "linux/uidgid.h"
#include <linux/kref.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid.h>
#include <linux/hashtable.h>
#include <linux/types.h>

#define BPF_NAMESPACE_HT_BITS 6

struct bpf_namespace_member {
	struct pid *thread_pid;
	struct hlist_node link;
};

struct bpf_namespace {
	struct ns_common ns;
	struct hlist_head members[1 << (BPF_NAMESPACE_HT_BITS)];
	struct user_namespace *user_ns;
} __randomize_layout;

extern spinlock_t bpf_ns_lock;
extern struct bpf_namespace init_bpf_ns;

#ifdef CONFIG_BPF_NAMESPACE
struct bpf_namespace *copy_bpf_ns(unsigned long flags,
				  struct user_namespace *user_ns,
				  struct bpf_namespace *old_bpf_ns);

static inline void get_bpf_ns(struct bpf_namespace *ns)
{
	refcount_inc(&ns->ns.count);
}

extern void free_bpf_ns(struct bpf_namespace *ns);

static inline void put_bpf_ns(struct bpf_namespace *ns)
{
	if (refcount_dec_and_test(&ns->ns.count))
		free_bpf_ns(ns);
}
#else /* CONFIG_BPF_NAMESPACE */
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/err.h>
static inline struct bpf_namespace *
copy_bpf_ns(unsigned long flags, struct user_namespace *user_ns,
	    struct bpf_namespace *old_bpf_ns)
{
	if (flags & CLONE_NEWBPF)
		return ERR_PTR(-EINVAL);
	return old_bpf_ns;
}
static inline void get_bpf_ns(struct bpf_namespace *ns)
{
}

static inline void put_bpf_ns(struct bpf_namespace *ns)
{
}
#endif /* CONFIG_BPF_NAMESPACE */

#endif
