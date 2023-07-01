use std::sync::atomic::{AtomicBool, Ordering};

use std::sync::Arc;
use std::mem;
use std::{thread, time};
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use moka::sync::Cache;

use anyhow::{bail, Result};
extern crate nix;

extern crate libbpf_rs;

#[path = "bpf/.output/xdp_switch.skel.rs"]
mod xdp_switch;

use xdp_switch::*;

extern crate blazesym;

use blazesym::symbolize;
use macaddr::{MacAddr, MacAddr6};

const ETH_ALEN: usize = 6;

#[repr(C)]
struct mac_address {
    mac: [u8; ETH_ALEN],
}

#[repr(C)]
struct iface_index {
    interface_index: u32,
    timestamp: u64,
}

#[repr(C)]
struct mac_address_iface_entry {
    mac: mac_address,
    iface: iface_index,
}


fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let m: MacAddr6;
    let mac_table: Cache<i32, i32> = Cache::builder().build();
    mac_table.insert(10, 10);

    let symbolizer = symbolize::Symbolizer::new();

    bump_memlock_rlimit()?;

    let network_interfaces = NetworkInterface::show()?;

    let skel_builder = XdpSwitchSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;

    network_interfaces.iter().try_for_each(|iface| -> Result<(), Box<dyn std::error::Error>> {
        let _link = skel.progs_mut().xdp_switch().attach_xdp(iface.index as i32)?;

        Ok(())
    })?;

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(skel.maps().new_discovered_entries_rb(), move |data| {
            event_handler(&symbolizer, data)
        })
        .unwrap();


    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        eprint!(".");
        thread::sleep(time::Duration::from_secs(1));
    }

    Ok(())
}

fn event_handler(symbolizer: &symbolize::Symbolizer, data: &[u8]) -> ::std::os::raw::c_int {
    if data.len() != mem::size_of::<mac_address_iface_entry>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<mac_address_iface_entry>()
        );
        return 1;
    }

    let event = unsafe { &*(data.as_ptr() as *const mac_address_iface_entry) };


    // if event.kstack_size <= 0 && event.ustack_size <= 0 {
    //     return 1;
    // }

    // let comm = std::str::from_utf8(&event.comm)
    //     .or::<Error>(Ok("<unknown>"))
    //     .unwrap();
    // println!("COMM: {} (pid={}) @ CPU {}", comm, event.pid, event.cpu_id);
    //
    // if event.kstack_size > 0 {
    //     println!("Kernel:");
    //     show_stack_trace(
    //         &event.kstack[0..(event.kstack_size as usize / mem::size_of::<u64>())],
    //         symbolizer,
    //         0,
    //     );
    // } else {
    //     println!("No Kernel Stack");
    // }

    // if event.ustack_size > 0 {
    //     println!("Userspace:");
    //     show_stack_trace(
    //         &event.ustack[0..(event.ustack_size as usize / mem::size_of::<u64>())],
    //         symbolizer,
    //         event.pid,
    //     );
    // } else {
    //     println!("No Userspace Stack");
    // }
    //
    // println!();
    0
}
