#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>

#include "xdp_switch.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct mac_address);
	__uint(key_size, sizeof(struct mac_address));
	__type(value, struct iface_index);
	__uint(value_size, sizeof(struct iface_index));
	__uint(max_entries, 256 * 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} mac_table SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} new_discovered_entries_rb SEC(".maps") __weak;

void register_source_mac_address_if_required(const struct xdp_md *ctx, const struct ethhdr *eth)
{
	__u64 current_time = bpf_ktime_get_ns();
	struct mac_address source_mac_addr;
	__builtin_memcpy(source_mac_addr.mac, eth->h_source, ETH_ALEN);

	struct iface_index *iface_for_source_mac = bpf_map_lookup_elem(&mac_table, &source_mac_addr);

	if (!iface_for_source_mac) {
		struct mac_address_iface_entry *new_entry = bpf_ringbuf_reserve(
			&new_discovered_entries_rb, sizeof(struct mac_address_iface_entry), 0);

		__builtin_memcpy(&new_entry->mac.mac, eth->h_source, ETH_ALEN);
		new_entry->iface.interface_index = ctx->ingress_ifindex;
		new_entry->iface.timestamp = current_time;

		bpf_map_update_elem(&mac_table, &new_entry->mac, &new_entry->iface, BPF_ANY);
		bpf_ringbuf_submit(new_entry, 0);
	} else {
		iface_for_source_mac->timestamp = current_time;
		bpf_map_update_elem(&mac_table, &source_mac_addr, iface_for_source_mac, BPF_ANY);
	}
}

// main router logic
SEC("xdp")
long xdp_switch(struct xdp_md *ctx)
{
	struct ethhdr *eth = (void *)(long)ctx->data;

	register_source_mac_address_if_required(ctx, eth);

	struct mac_address dest_mac_addr;
	__builtin_memcpy(dest_mac_addr.mac, eth->h_source, ETH_ALEN);

	struct iface_index *iface_to_redirect = bpf_map_lookup_elem(&mac_table, &dest_mac_addr);

	return bpf_redirect(iface_to_redirect->interface_index, 0);
}