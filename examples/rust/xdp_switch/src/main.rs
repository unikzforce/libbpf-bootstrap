use std::sync::atomic::{AtomicBool, Ordering};

use std::sync::{Arc, Mutex};
use std::mem;
use std::{thread, time};
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use moka::sync::Cache;
use clap::{Parser, Subcommand};

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
use moka::notification::RemovalCause;

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


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long)]
    exclude: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let symbolizer = symbolize::Symbolizer::new();

    bump_memlock_rlimit()?;

    let network_interfaces: Vec<NetworkInterface> = NetworkInterface::show()?;

    let filtered_network_interfaces: Vec<_> = network_interfaces
        .into_iter()
        .filter(|iface| iface.name != cli.exclude)
        .collect();

    for iface in filtered_network_interfaces {
        println!("iface name {}", iface.name);
    }

    let skel_builder = XdpSwitchSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let skel = Arc::new(Mutex::new(open_skel.load()?));

    let skel_for_eviction_clone = Arc::clone(&skel);
    let eviction_listener = move |k: Arc<mac_address>, v: iface_index, cause: RemovalCause| {
        if let Ok(mut skel_guard) = skel_for_eviction_clone.lock() {
            let skel_ref = &mut *skel_guard;
            let maps = skel_ref.maps();
            let kernel_mac_table = maps.mac_table();
            let b: [u8; 6] = [1; 6];
            kernel_mac_table.delete(&b);
        } else {
            eprintln!("Failed to get mutable access to skel in eviction_listener");
        }
    };

    let user_mac_table: Arc<Mutex<Cache<mac_address, iface_index>>> = Arc::new(
        Mutex::new(
            Cache::builder()
                .eviction_listener(eviction_listener)
                .build(),
        )
    );

    let skel_for_attach_clone = Arc::clone(&skel);
    network_interfaces.iter().try_for_each(move |iface| -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(mut skel_guard) = skel_for_attach_clone.lock() {
            let skel_ref = &mut *skel_guard;
            let progs_mut = &mut skel_ref.progs_mut();
            let _link = progs_mut.xdp_switch().attach_xdp(iface.index as i32)?;
        } else {
            eprintln!("Failed to get mutable access to skel in main");
        }
        Ok(())
    })?;

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    let skel_for_new_discoveries_clone = Arc::clone(&skel);
    if let Ok(mut skel_guard) = skel_for_new_discoveries_clone.lock() {
        let skel_ref = &mut *skel_guard;
        let maps = skel_ref.maps();
        builder
            .add(maps.new_discovered_entries_rb(), move |data| {
                new_discovered_entry_handler(&symbolizer, data, &(*user_mac_table.lock().unwrap()))
            })
            .unwrap();
    } else {
        eprintln!("Failed to get mutable access to skel in main");
    }


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
