#include "linux/list.h"
#include "linux/uidgid.h"
#include <linux/bpf_namespace.h>
#include <linux/refcount.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/spinlock_types.h>

DEFINE_SPINLOCK(bpf_ns_lock);

struct bpf_namespace init_bpf_ns = {
	.ns.count = REFCOUNT_INIT(2),
	.ns.ops = NULL, //currently bpf_ns proc ops are not implemented
	.ns.inum = 0,
	.user_ns = &init_user_ns,
	.members = { [0 ...((1 << (BPF_NAMESPACE_HT_BITS)) - 1)] =
			     HLIST_HEAD_INIT }
};

#ifdef CONFIG_BPF_NAMESPACE
struct bpf_namespace *copy_bpf_ns(unsigned long flags,
				  struct user_namespace *user_ns,
				  struct bpf_namespace *old_bpf_ns)
{
	if (flags & CLONE_NEWBPF)
		return old_bpf_ns;
	else {
		return old_bpf_ns;
	}
}

void free_bpf_ns(struct bpf_namespace *ns)
{
}
#endif
