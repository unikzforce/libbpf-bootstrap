


suppose we have these devices:

- client1_vm:ens192    2.2.2.1/24
- xdp_switch_vm:ens192   --- which is connected to ---> client1_vm:ens192
- xpd_switch_vm:ens224   --- which is connected to ---> client2_vm:ens192
- client2_vm:ens192    2.2.2.2/24

be careful to disable security network segments ( vmware)
also both interfaces on xdp_switch_vm should be PROMISC on.

so in vmware configurations for both segments:

- promiscuous mode --> tick Override --> ACCEPT
- Mac Address changes --> tick override --> ACCEPT
- Forged transmits --> tick override --> ACCEPT


the current problem that is needed to be solved:

using normal XDP program i cannot redirect a single packet to multiple network ports on the switch,
so currently this switch is just working like a bridge. we probably should switch to AF_XDP to be able
to copy packet multiple times to implement `Unknown Unicast Flooding`. maybe it would be much easier to 
implement that via golang --> see here: https://pkg.go.dev/gvisor.dev/gvisor/pkg/xdp + https://github.com/google/gvisor


compile:
```
cd examples/rust/xdp_switch
cargo clean
cargo build --release
```

execute:
```
./examples/rust/target/release/xdp_switch --includes ens192 ens224
```