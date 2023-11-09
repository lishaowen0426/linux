#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/init.h>
#include <linux/printk.h>

static int nocore_netdev_notifier_call(struct notifier_block *nb,
				       unsigned long state, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	pr_info("nocore: dev = %s\n", dev->name);
	return 0;
}

static struct notifier_block nocore_netdev_notifier = {
	.notifier_call = nocore_netdev_notifier_call,
};

void __init net_nocore_init(void)
{
	register_netdevice_notifier(&nocore_netdev_notifier);
	return;
}
