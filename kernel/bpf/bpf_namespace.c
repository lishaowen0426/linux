#include "asm-generic/errno-base.h"
#include "linux/gfp_types.h"
#include "linux/list.h"
#include "linux/uidgid.h"
#include <linux/bpf_namespace.h>
#include <linux/refcount.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <linux/pid.h>

#define NS_INUM 0 // this should be fixed once proc is implemented

DEFINE_MUTEX(bpf_ns_lock);

static struct kmem_cache *bpf_member_cachep;
static struct kmem_cache *bpf_ns_cachep;

struct bpf_namespace init_bpf_ns = {
	.ns.count = REFCOUNT_INIT(2),
	.ns.ops = NULL, //currently bpf_ns proc ops are not implemented
	.ns.inum = NS_INUM,
	.user_ns = &init_user_ns,
	.members = { [0 ...((1 << (BPF_NAMESPACE_HT_BITS)) - 1)] =
			     HLIST_HEAD_INIT }
};

#ifdef CONFIG_BPF_NAMESPACE

void __init bpf_ns_init(void)
{
	bpf_member_cachep =
		KMEM_CACHE(bpf_namespace_member, SLAB_PANIC | SLAB_ACCOUNT);
	bpf_ns_cachep = KMEM_CACHE(bpf_namespace, SLAB_PANIC | SLAB_ACCOUNT);
	return;
}

static void init_bpf_ns_common(struct ns_common *ns)
{
	refcount_set(&(ns->count), 1);
	ns->ops = NULL;
	ns->inum = NS_INUM;
}

static struct bpf_namespace *create_bpf_namespace(struct user_namespace *user)
{
	struct bpf_namespace *new_bpf_ns =
		kmem_cache_zalloc(bpf_ns_cachep, GFP_KERNEL);
	if (new_bpf_ns == NULL) {
		return new_bpf_ns;
	}

	init_bpf_ns_common(&(new_bpf_ns->ns));
	hash_init(new_bpf_ns->members);
	new_bpf_ns->user_ns = user;

	return new_bpf_ns;
}

static void join_bpf_ns(struct bpf_namespace_member *member,
			struct bpf_namespace *ns)
{
	uintptr_t key = (uintptr_t)(member->thread_pid);
	hash_add(ns->members, &(member->link), key);
	return;
}

static void leave_bpf_ns(struct bpf_namespace *ns)
{
	int bkt;
	struct bpf_namespace_member *member;
	struct pid *thread_pid = task_pid(current);
	hash_for_each(ns->members, bkt, member, link) {
		if (member->thread_pid == thread_pid) {
			hash_del(&(member->link));
			kmem_cache_free(bpf_member_cachep, member);
			break;
		}
	}
}

struct bpf_namespace *copy_bpf_ns(unsigned long flags,
				  struct user_namespace *user_ns,
				  struct bpf_namespace *old_bpf_ns)
{
	int err;
	struct bpf_namespace_member *bpf_member;
	struct bpf_namespace *new_bpf_ns;

	bpf_member = kmem_cache_zalloc(bpf_member_cachep, GFP_KERNEL);
	if (bpf_member == NULL) {
		goto out;
	}
	bpf_member->thread_pid = task_pid(current);
	pid_t debug_pid = pid_nr(bpf_member->thread_pid);

	if (!(flags & CLONE_NEWBPF)) {
		// join the old_bpf_ns
		mutex_lock(&bpf_ns_lock);
		join_bpf_ns(bpf_member, old_bpf_ns);
		get_bpf_ns(old_bpf_ns);
		mutex_unlock(&bpf_ns_lock);
		pr_info("pid(global) %d join existing bpf ns", debug_pid);
		return old_bpf_ns;

	} else {
		new_bpf_ns = create_bpf_namespace(user_ns);
		if (new_bpf_ns == NULL) {
			goto out_free_member;
		}
		join_bpf_ns(bpf_member, new_bpf_ns);
		pr_info("pid(global) %d join new bpf ns", debug_pid);
		return new_bpf_ns;
	}

out_free_member:
	kmem_cache_free(bpf_member_cachep, bpf_member);
out:
	err = -ENOMEM;
	return ERR_PTR(err);
}

void put_bpf_ns(struct bpf_namespace *ns)
{
	pid_t debug_pid = pid_nr(task_pid(current));
	pr_info("pid(global) %d leave bpf ns", debug_pid);
	mutex_lock(&bpf_ns_lock);
	leave_bpf_ns(ns);
	mutex_unlock(&bpf_ns_lock);

	if (refcount_dec_and_test(&ns->ns.count))
		free_bpf_ns(ns);
}

void free_bpf_ns(struct bpf_namespace *ns)
{
	kmem_cache_free(bpf_ns_cachep, ns);
}
#endif
