#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u32 interfaces[20] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
__u32 number_of_interfaces = 20;

SEC("tc")
int unknown_unicast_flooding(struct __sk_buff *skb)
{
	bpf_printk(
		"///////////////////////////////////////////////////////////////////////////////////////////////////");
	// we can use current_time as something like a unique identifier for packet
	__u64 current_time = bpf_ktime_get_ns();
	struct ethhdr *eth = (void *)(long)skb->data;

	if ((void *)(eth + 1) > (void *)(long)skb->data_end)
		return BPF_DROP;

	bpf_printk(
		"///////////// id = %llx, interface = %d, Packet received, source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		current_time, skb->ingress_ifindex, eth->h_source[0], eth->h_source[1],
		eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

	bpf_printk(
		"///////////// id = %llx, interface = %d, Packet received, dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		current_time, skb->ingress_ifindex, eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

	int ingress_ifindex = skb->ingress_ifindex;

	if (number_of_interfaces >= 20) {
		return BPF_DROP;
	}

	bpf_printk("///////////// id = %llx, interface = %d, start to multicast\n", current_time, skb->ingress_ifindex);

	for (unsigned int iface_index = 0; iface_index < number_of_interfaces; iface_index++) {
		if (iface_index >= 20) {
			break;
		}

		if (interfaces[iface_index] != ingress_ifindex) {
			bpf_clone_redirect(skb, interfaces[iface_index], 0);
			bpf_printk("///////////// id = %llx, multicast: redirection to %d \n",
				   current_time, interfaces[iface_index]);
		}
	}

	return TC_ACT_OK;
}
