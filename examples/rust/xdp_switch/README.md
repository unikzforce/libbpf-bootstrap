


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