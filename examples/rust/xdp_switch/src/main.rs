use std::sync::atomic::{AtomicBool, Ordering};

use std::sync::Arc;
use std::mem;
use std::{thread, time};
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use moka::sync::Cache;

use std::cell::{RefCell, UnsafeCell};
use std::rc::Rc;

use anyhow::{bail, Result};
extern crate nix;

extern crate libbpf_rs;

#[path = "bpf/.output/xdp_switch.skel.rs"]
mod xdp_switch;

use xdp_switch::*;

extern crate blazesym;

use blazesym::symbolize;
use libbpf_rs::Map;
use macaddr::{MacAddr, MacAddr6};
use moka::notification::RemovalCause;

struct KernelMacTable {
    table: &'static Map,
}

unsafe impl Sync for KernelMacTable {}

unsafe impl Send for KernelMacTable {}

const ETH_ALEN: usize = 6;

#[repr(C)]
#[derive(Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
struct mac_address {
    mac: [u8; ETH_ALEN],
}

#[repr(C)]
#[derive(Clone)]
struct iface_index {
    interface_index: u32,
    timestamp: u64,
}

#[repr(C)]
#[derive(Clone)]
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

    let symbolizer = symbolize::Symbolizer::new();

    bump_memlock_rlimit()?;

    let network_interfaces = NetworkInterface::show()?;

    let skel_builder = XdpSwitchSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = Rc::new(open_skel.load());

    let kernel_mac_table =  Arc::new(KernelMacTable {
        table: skel.clone().unwrap().maps().mac_table(),
    });


    let eviction_listener = move |k: Arc<mac_address>, v: iface_index, cause: RemovalCause| {
        unsafe {
            // TODO do the actual implementation
            let b: [u8; 6] = [1; 6];
            let kernel_m_t = kernel_mac_table.table;
            let _ = kernel_m_t.delete(&b);
        }
    };

    let user_mac_table: Cache<mac_address, iface_index> = Cache::builder()
        .eviction_listener(eviction_listener)
        .build();

    network_interfaces.iter().try_for_each(|iface| -> Result<(), Box<dyn std::error::Error>> {
        let _link = skel.unwrap().progs_mut().xdp_switch().attach_xdp(iface.index as i32)?;

        Ok(())
    })?;

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(skel.unwrap().maps().new_discovered_entries_rb(), move |data| {
            new_discovered_entry_handler(&symbolizer, data, &user_mac_table)
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

fn new_discovered_entry_handler(symbolizer: &symbolize::Symbolizer, data: &[u8], mac_table: &Cache<mac_address, iface_index>) -> ::std::os::raw::c_int {
    if data.len() != mem::size_of::<mac_address_iface_entry>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<mac_address_iface_entry>()
        );
        return 1;
    }

    let event = unsafe { &*(data.as_ptr() as *const mac_address_iface_entry) };

    // mac_table.
    //
    // match mac_table.get(&event.mac) {
    //     Some(value) => println!("it was there"),
    //     None =>  println!("it wasn't there"),
    // };
    0
}
