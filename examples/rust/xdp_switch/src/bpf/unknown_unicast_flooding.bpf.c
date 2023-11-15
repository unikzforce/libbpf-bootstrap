#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u32 interfaces[20] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
__u32 number_of_interfaces = 20 - 1;

SEC("tc")
long unknown_unicast_flooding(struct __sk_buff *skb)
{

	__u64 current_time = bpf_ktime_get_ns();

	struct ethhdr *eth = (void *)(long)skb->data;

	// Additional check after the adjustment
	if ((void *)(eth + 1) > (void *)(long)skb->data_end)
		return BPF_DROP;

	int ingress_ifindex = skb->ingress_ifindex;

	if (number_of_interfaces >= 19) {
		return BPF_DROP;
	}

	for (unsigned int iface_index = 0; iface_index < number_of_interfaces; iface_index++) {
		if (iface_index >= 20) {
			break;
		}

		if (interfaces[iface_index] != ingress_ifindex) {
			bpf_clone_redirect(skb, interfaces[iface_index], 0);
		}
	}

	return BPF_DROP;

}
