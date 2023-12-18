#ifndef _LINUX_BPF_NAMESPACE_H
#define _LINUX_BPF_NAMESPACE_H

#include "linux/compiler_types.h"
#include "linux/sched.h"
#include "linux/uidgid.h"
#include <linux/kref.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/mutex.h>

#define BPF_NAMESPACE_HT_BITS 6

struct bpf_namespace_member {
	struct pid *thread_pid;
	struct hlist_node link;
};

struct bpf_namespace {
	uintptr_t id;
	struct ns_common ns;
	struct hlist_head members[1 << (BPF_NAMESPACE_HT_BITS)];
	u32 member_count; //ns.count should be equal to ns.count, but NOT NECESSARILY
	struct user_namespace *user_ns;
	struct mutex mtx; // protect this bpf_ns
} __randomize_layout;

extern struct mutex bpf_ns_lock;
extern struct bpf_namespace init_bpf_ns;
extern struct bpf_namespace_member init_bpf_ns_member;

#ifdef CONFIG_BPF_NAMESPACE
struct bpf_namespace *copy_bpf_ns(unsigned long flags,
				  struct user_namespace *user_ns,
				  struct bpf_namespace *old_bpf_ns);

static inline void get_bpf_ns(struct bpf_namespace *ns)
{
	refcount_inc(&ns->ns.count);
}

extern void free_bpf_ns(struct bpf_namespace *ns);

extern void put_bpf_ns(struct bpf_namespace *ns);

extern void task_join_bpf(struct task_struct *tsk);
extern void task_exit_bpf(struct task_struct *tsk);

extern void bpf_ns_init(void);

static inline struct bpf_namespace *task_bpf_ns(struct task_struct *tsk)
{
	return tsk->nsproxy->bpf_ns;
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

static inline void bpf_ns_init(void)
{
}
static inline void task_join_bpf(struct task_struct *tsk)
{
}
static inline void task_exit_bpf(struct task_struct *tsk)
{
}
#endif /* CONFIG_BPF_NAMESPACE */

#endif
