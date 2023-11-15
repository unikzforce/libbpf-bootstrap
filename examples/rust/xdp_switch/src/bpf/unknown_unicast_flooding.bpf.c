#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u32 interfaces[20] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
__u32 number_of_interfaces = 20;

SEC("tc")
long unknown_unicast_flooding(struct __sk_buff *skb)
{

	__u64 current_time = bpf_ktime_get_ns();

	int ingress_ifindex = skb->ingress_ifindex;

	for (unsigned int iface_index = 0; iface_index < number_of_interfaces; iface_index++) {
		if (interfaces[iface_index] != ingress_ifindex) {
			bpf_clone_redirect(skb, interfaces[iface_index], 0);
		}
	}

	return BPF_DROP;

//	bpf_printk(
//		"----------------------------------------------------------------------------------------------------");
//	// we can use current_time as something like a unique identifier for packet
//
//
//	struct ethhdr *eth = (void *)(long)ctx->data;
//
//	// Additional check after the adjustment
//	if ((void *)(eth + 1) > (void *)(long)ctx->data_end)
//		return XDP_ABORTED;
//
//	bpf_printk(
//		"id = %llx, interface = %d, Packet received, source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//		current_time, ctx->ingress_ifindex, eth->h_source[0], eth->h_source[1],
//		eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
//
//	bpf_printk(
//		"id = %llx, interface = %d, Packet received, dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//		current_time, ctx->ingress_ifindex, eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
//		eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}
