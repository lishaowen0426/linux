#include "linux/gfp_types.h"
#include "linux/list.h"
#include "linux/mutex.h"
#include "linux/sched/task.h"
#include "linux/types.h"
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
#include <linux/list.h>
#include <linux/panic.h>

#define NS_INUM 0 // this should be fixed once proc is implemented

DEFINE_MUTEX(bpf_ns_lock);

static struct kmem_cache *bpf_member_cachep;
static struct kmem_cache *bpf_ns_cachep;

struct bpf_namespace init_bpf_ns = {
	.ns.count = REFCOUNT_INIT(1), //init_task
	.ns.ops = NULL, //currently bpf_ns proc ops are not implemented
	.ns.inum = NS_INUM,
	.user_ns = &init_user_ns,
	.members = { [0 ...((1 << (BPF_NAMESPACE_HT_BITS)) - 1)] =
			     HLIST_HEAD_INIT },
	.member_count = 0,
	.id = (uintptr_t)&init_bpf_ns,
};

#ifdef CONFIG_BPF_NAMESPACE

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
	new_bpf_ns->id = (uintptr_t)new_bpf_ns;
	mutex_init(&(new_bpf_ns->mtx));

	return new_bpf_ns;
}

static void join_bpf_ns(struct bpf_namespace_member *member,
			struct bpf_namespace *ns)
{
	uintptr_t key = (uintptr_t)(member->thread_pid);
	hash_add(ns->members, &(member->link), key);
	ns->member_count += 1;
	return;
}

void task_join_bpf(struct task_struct *tsk)
{
	struct pid *thread_pid = get_task_pid(tsk, PIDTYPE_PID);
	pid_t debug_pid = pid_nr(thread_pid);
	struct bpf_namespace_member *member =
		kmem_cache_zalloc(bpf_member_cachep, GFP_KERNEL);
	if (member == NULL) {
		panic("Could not allocate bpf_namespace_member");
	}
	member->thread_pid = thread_pid;

	struct bpf_namespace *ns = task_bpf_ns(tsk);

	mutex_lock(&(ns->mtx));
	join_bpf_ns(member, ns);
	mutex_unlock(&(ns->mtx));
	pr_info("global pid %d join bpf ns: %lx", debug_pid, ns->id);
}

static void leave_bpf_ns(struct bpf_namespace *ns, struct pid *thread_pid)
{
	int bkt;
	struct bpf_namespace_member *member;
	hash_for_each(ns->members, bkt, member, link) {
		if (member->thread_pid == thread_pid) {
			hash_del(&(member->link));
			if (ns->member_count == 0) {
				panic("bpf_namespace wrong member_count");
			} else {
				ns->member_count -= 1;
			}
			put_pid(thread_pid);
			kmem_cache_free(bpf_member_cachep, member);
			goto success;
		}
	}
	panic("cannot find self in leave_bpf_ns");
success:
	return;
}
void task_exit_bpf(struct task_struct *tsk)
{
	struct pid *thread_pid = get_task_pid(tsk, PIDTYPE_PID);
	pid_t debug_pid = pid_nr(thread_pid);
	struct bpf_namespace *ns = task_bpf_ns(tsk);
	mutex_lock(&(ns->mtx));
	leave_bpf_ns(ns, thread_pid);
	mutex_unlock(&(ns->mtx));
	pr_info("global pid %d leave bpf ns: %lx", debug_pid, ns->id);
}

void __init bpf_ns_init(void)
{
	bpf_member_cachep =
		KMEM_CACHE(bpf_namespace_member, SLAB_PANIC | SLAB_ACCOUNT);
	bpf_ns_cachep = KMEM_CACHE(bpf_namespace, SLAB_PANIC | SLAB_ACCOUNT);

	mutex_init(&(init_bpf_ns.mtx));

	struct bpf_namespace_member *init_bpf_member =
		kmem_cache_zalloc(bpf_member_cachep, GFP_KERNEL);
	if (init_bpf_member == NULL) {
		panic("Could not allocate bpf_namespace_member for init_task");
	}
	init_bpf_member->thread_pid = get_task_pid(&init_task, PIDTYPE_PID);

	join_bpf_ns(init_bpf_member, &init_bpf_ns);
	return;
}

struct bpf_namespace *copy_bpf_ns(unsigned long flags,
				  struct user_namespace *user_ns,
				  struct bpf_namespace *old_bpf_ns)
{
	/*
     * when this is called, the new process has
     * not been assigned its pid.
     *
     * we just set up its bpf_namespace.  The new process
     * should remember to join its bpf_namespace
     *
     * */
	int err;

	if (!(flags & CLONE_NEWBPF)) {
		// join the old_bpf_ns
		get_bpf_ns(old_bpf_ns);
		return old_bpf_ns;

	} else {
		//refcount is set to 1 inside
		struct bpf_namespace *new_bpf_ns =
			create_bpf_namespace(user_ns);
		if (new_bpf_ns == NULL) {
			goto out;
		}
		return new_bpf_ns;
	}

out:
	err = -ENOMEM;
	return ERR_PTR(err);
}

void put_bpf_ns(struct bpf_namespace *ns)
{
	if (refcount_dec_and_test(&ns->ns.count)) {
		if (ns->member_count != 0) {
			panic("put_bpf_ns: wrong member_count :%d",
			      ns->member_count);
		}
		free_bpf_ns(ns);
	}
}

void free_bpf_ns(struct bpf_namespace *ns)
{
	kmem_cache_free(bpf_ns_cachep, ns);
}
#endif
