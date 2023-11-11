#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>

#include "xdp_switch.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


__u32 first_interface = 0;
__u32 second_interface = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct mac_address);
	__uint(key_size, sizeof(struct mac_address));
	__type(value, struct iface_index);
	__uint(value_size, sizeof(struct iface_index));
	__uint(max_entries, 256 * 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} mac_table SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} new_discovered_entries_rb SEC(".maps") __weak;

void register_source_mac_address_if_required(const struct xdp_md *ctx, const struct ethhdr *eth,
					     __u64 current_time)
{
	bpf_printk("id = %llx, learning-process: register source mac address if required\n",
		   current_time);
	struct mac_address source_mac_addr;
	__builtin_memcpy(source_mac_addr.mac, eth->h_source, ETH_ALEN);

	bpf_printk(
		"id = %llx, learning-process: check if we already have registered source mac address \n",
		current_time);

	struct iface_index *iface_for_source_mac =
		bpf_map_lookup_elem(&mac_table, &source_mac_addr);

	if (!iface_for_source_mac) {
		bpf_printk(
			"id = %llx, learning-process: have NOT Found an already registered entry for source mac address \n",
			current_time);

		struct mac_address_iface_entry new_entry = {
			.mac = { .mac = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } },
			.iface = { .interface_index = ctx->ingress_ifindex,
				   .timestamp = current_time }
		};

		__builtin_memset(&new_entry, 0, sizeof(new_entry));

		__builtin_memcpy(new_entry.mac.mac, eth->h_source, ETH_ALEN);
		new_entry.iface.interface_index = ctx->ingress_ifindex;
		new_entry.iface.timestamp = current_time;

		bpf_printk(
			"id = %llx, learning-process: have NOT found + trying to update mac_table map\n",
			current_time);

		bpf_map_update_elem(&mac_table, &(new_entry.mac), &(new_entry.iface), BPF_ANY);
		//		bpf_ringbuf_submit(new_entry, 0);

		bpf_printk(
			"id = %llx, learning-process: have NOT found + trying to submit data to new_discovered map\n",
			current_time);
		bpf_ringbuf_output(&new_discovered_entries_rb, &new_entry, sizeof(new_entry), 0);
	} else {
		bpf_printk(
			"id = %llx, learning-process: have Found an already registered entry for source mac address \n",
			current_time);
		iface_for_source_mac->timestamp = current_time;
		bpf_map_update_elem(&mac_table, &source_mac_addr, iface_for_source_mac, BPF_ANY);
	}
}

SEC("xdp")
long xdp_switch(struct xdp_md *ctx)
{
	// we can use current_time as something like a unique identifier for packet
	__u64 current_time = bpf_ktime_get_ns();

	struct ethhdr *eth = (void *)(long)ctx->data;

	// Additional check after the adjustment
	if ((void *)(eth + 1) > (void *)(long)ctx->data_end)
		return XDP_ABORTED;

	bpf_printk("id = %llx, interface = %d, Packet received, source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   current_time,
		   ctx->ingress_ifindex,
		   eth->h_source[0],
		   eth->h_source[1],
		   eth->h_source[2],
		   eth->h_source[3],
		   eth->h_source[4],
		   eth->h_source[5]);

	bpf_printk("id = %llx, interface = %d, Packet received, dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   current_time,
		   ctx->ingress_ifindex,
		   eth->h_dest[0],
		   eth->h_dest[1],
		   eth->h_dest[2],
		   eth->h_dest[3],
		   eth->h_dest[4],
		   eth->h_dest[5]);

	register_source_mac_address_if_required(ctx, eth, current_time);

	struct mac_address dest_mac_addr;
	__builtin_memcpy(dest_mac_addr.mac, eth->h_dest,
			 ETH_ALEN); // Changed from h_source to h_dest

	bpf_printk("id = %llx, interface = %d, lookup mac_table for matching redirect iface, h_dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   current_time,
		   ctx->ingress_ifindex,
		   eth->h_dest[0],
		   eth->h_dest[1],
		   eth->h_dest[2],
		   eth->h_dest[3],
		   eth->h_dest[4],
		   eth->h_dest[5]);

	struct iface_index *iface_to_redirect = bpf_map_lookup_elem(&mac_table, &dest_mac_addr);

	if (!iface_to_redirect) {
		if (eth->h_dest[0] == 0xff &&
		    eth->h_dest[1] == 0xff &&
		    eth->h_dest[2] == 0xff &&
		    eth->h_dest[3] == 0xff &&
		    eth->h_dest[4] == 0xff &&
		    eth->h_dest[5] == 0xff) {
			bpf_printk("id = %llx, interface = %d, in case eth-h_dest==ff:ff:ff:ff:ff:ff we should do unknown unicast flooding\n", current_time, ctx->ingress_ifindex);
			// in this case we need to redirect to interfaces that is not equal to ctx->ingress_ifindex
			// the problem is that this program would work if the switch have 2 interfaces not more,
			// because in this type of XDP program we cannot redirect a packet to two interfaces.
			if (ctx->ingress_ifindex != first_interface) {
				bpf_printk("id = %llx, interface = %d, redirecting to interface %d \n", current_time, ctx->ingress_ifindex, first_interface);
				return bpf_redirect(first_interface, 0);
			}
			if (ctx->ingress_ifindex != second_interface) {
				bpf_printk("id = %llx, interface = %d, redirecting to interface %d \n", current_time, ctx->ingress_ifindex, second_interface);
				return bpf_redirect(second_interface, 0);
			}
		}
		bpf_printk("id = %llx, interface = %d, nothing has been found so will do XDP_PASS\n", current_time, ctx->ingress_ifindex);
		return XDP_PASS; // If the destination MAC isn't found, simply pass the packet
	}

	bpf_printk("id = %llx, interface = %d, match found. do the redirection\n", current_time, ctx->ingress_ifindex);
	return bpf_redirect(iface_to_redirect->interface_index, 0);
}
