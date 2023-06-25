#ifndef ROUTER_H
#define ROUTER_H
#include <linux/types.h>

struct mac_address {
	unsigned char mac[ETH_ALEN]; // MAC address
};

struct iface_index {
	__u32 interface_index;
	__u64 timestamp;
};

struct mac_address_iface_entry {
	struct mac_address mac;
	struct iface_index iface;
};



// max # of vlan for trunked ports
#define MAX_TRUNK_VLANS 8

// max # of interfaces
#define MAX_IFACES 16

enum vlan_mode { VLAN_ACCESS = 0, VLAN_TRUNK = 1 };

struct if_vlan_info {
	// enum vlan_mode
	__u8 mode;

	// native vlan id (for both trunk and access)
	__be16 pvid;

	// trunked vlan id (for trunk)
	__be16 trunks[MAX_TRUNK_VLANS];
};

struct vlan_hdr {
	__be16 vlan_id;
	__be16 inner_ether_proto;
};

#endif // ROUTER_H