/*
 * Priority booster for services on specific ports
 */

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SP");
MODULE_DESCRIPTION("Priority booster for services on specific ports");
MODULE_VERSION("0.0.1");

#define DEFAULT_PORT 2404
#define DEFAULT_PRIORITY 10
#define FLAG_ENABLED 1
#define FLAG_DISABLED 0

static int priority_port = DEFAULT_PORT; /* default port */
module_param(priority_port, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(priority_port, "Port number to prioritize");

static int priority_boost = DEFAULT_PRIORITY; /* default priority boost */
module_param(priority_boost, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(priority_boost, "Priority boost value");

static struct nf_hook_ops nfho;

static unsigned int prioritize_service(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);

    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(priority_port)) {
        skb->priority = priority_boost;
    }

    return NF_ACCEPT;
}

static int __init prioritize_init(void)
{
    nfho.hook = prioritize_service;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    int ret = nf_register_net_hook(&init_net, &nfho);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register net hook\n");
        return ret;
    }

    return 0;
}

static void __exit prioritize_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(prioritize_init);
module_exit(prioritize_exit);