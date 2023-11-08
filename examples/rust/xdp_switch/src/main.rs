use std::sync::atomic::{AtomicBool, Ordering};

use std::sync::{Arc, Mutex};
use std::mem;
use std::{thread, time};
use std::time::Duration;
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use moka::sync::Cache;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;

use anyhow::{bail, Result};
use crossbeam_channel::{unbounded, Receiver, Sender};

extern crate nix;

extern crate libbpf_rs;

#[path = "bpf/.output/xdp_switch.skel.rs"]
mod xdp_switch;

use xdp_switch::*;

use chrono::Utc;
use libbpf_rs::{Link, MapFlags};
use moka::notification::RemovalCause;
use unsafe_send_sync::UnsafeSend;

const ETH_ALEN: usize = 6;

#[repr(C)]
#[derive(Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
struct mac_address {
    mac: [u8; ETH_ALEN],
}

#[repr(C)]
#[derive(Debug,  Clone)]
struct iface_index {
    interface_index: u32,
    timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
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
    #[clap(short, long, value_delimiter = ' ', num_args = 1..)]
    /// List of items to exclude
    excludes: Vec<String>,

    #[clap(short, long, value_delimiter = ' ', num_args = 1..)]
    /// List of items to include
    includes: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, receiver): (Sender<mac_address_iface_entry>, Receiver<mac_address_iface_entry>) = unbounded();

    let cli = Cli::parse();

    cli.excludes.iter().for_each( | item | {
        println!("excluded item {}", item);
    });

    cli.includes.iter().for_each( | item | {
        println!("included item {}", item);
    });

    bump_memlock_rlimit()?;

    let network_interfaces: Vec<NetworkInterface> = NetworkInterface::show()?;

    let filtered_network_interfaces: Vec<_> = if !cli.includes.is_empty() {
        network_interfaces
            .into_iter()
            .filter(|iface| cli.includes.contains(&iface.name))
            .collect()
    } else {
        network_interfaces
            .into_iter()
            .filter(|iface| !cli.excludes.contains(&iface.name))
            .collect()
    };

    let skel_builder = XdpSwitchSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
    open_skel.bss().switch_interfaces_count = filtered_network_interfaces.len() as u32;

    for (i, iface) in filtered_network_interfaces.iter().enumerate() {
        open_skel.bss().switch_interfaces[i] = iface.index;
    }

    let skel = Arc::new(UnsafeSend::new(open_skel.load()?));

    let skel_for_eviction_clone = Arc::clone(&skel);
    let eviction_listener = move |k: Arc<mac_address>, v: iface_index, _: RemovalCause| {
        let maps = skel_for_eviction_clone.as_ref().maps();
        let kernel_mac_table = maps.mac_table();
        let existing_kernel_entry = kernel_mac_table.lookup(&k.mac, MapFlags::ANY);

        match existing_kernel_entry {
            Ok(Some(data)) => {
                // The data is available, now we can try to convert it to iface_index struct
                if data.len() == std::mem::size_of::<iface_index>() {
                    let iface_index_data = unsafe { &*(data.as_ptr() as *const iface_index) };

                    let timestamp_seconds = iface_index_data.timestamp / 1_000_000_000; // Convert timestamp to seconds

                    let current_time = Utc::now().timestamp();
                    let time_difference = current_time - timestamp_seconds as i64;

                    if time_difference < 30 {
                        sender.send(mac_address_iface_entry {
                            mac: *k.clone().as_ref(),
                            iface: v.clone(),
                        }).expect("oeuoeu");
                    } else {
                        let _ = kernel_mac_table.delete(&k.mac);
                    }
                } else {
                    eprintln!("Invalid data size for iface_index");
                }
            }
            Ok(None) => {
                println!("No entry found for the given MAC address");
            }
            Err(err) => {
                eprintln!("Error while looking up the MAC address: {:?}", err);
            }
        }
    };

    let user_mac_table: Arc<UnsafeSend<Cache<mac_address, iface_index>>> = Arc::new(
        UnsafeSend::new(
            Cache::builder()
                .eviction_listener(eviction_listener)
                .time_to_live(Duration::from_secs(30))
                .build(),
        )
    );

    let user_mac_table_clone = Arc::clone(&user_mac_table);
    let _receiver_thread = thread::spawn(move || {
        while let Ok(item) = receiver.recv() {
            let _ = user_mac_table_clone.as_ref().insert(item.mac, item.iface);
        }
    });


    let skel_for_attach_clone = Arc::clone(&skel);
    let links: Arc<Mutex<Vec<Link>>> = Arc::new(Mutex::new(Vec::new()));
    let cloned_links = Arc::clone(&links);
    filtered_network_interfaces.iter().try_for_each(move |iface| -> Result<(), Box<dyn std::error::Error>> {
        // if let Some(skel_for_attach_inner) = Arc::get_mut(&mut skel_for_attach_clone) {
        let skel_mut_ref: &mut UnsafeSend<XdpSwitchSkel> = unsafe {
            &mut *(Arc::as_ptr(&skel_for_attach_clone) as *mut _)
        };
        println!("trying to attach to network card {:?}", iface.name);
        let _link = skel_mut_ref.progs_mut().xdp_switch().attach_xdp(iface.index as i32)?;

        let mut links_guard = cloned_links.lock().unwrap();
        links_guard.push(_link);

        // skel_mut_ref.links = XdpSwitchLinks {
        //     xdp_switch: Some(_link)
        // };

        println!("successful attachment to network card {:?}", iface.name);
        // } else {
        //     eprintln!("Failed to obtain mutable reference to skel");
        // }
        Ok(())
    })?;

    let links_guard = links.lock().unwrap();
    for link in &*links_guard {
        println!("link {:?}", link)
    }

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    let skel_for_new_discoveries_clone = Arc::clone(&skel);

    let maps = skel_for_new_discoveries_clone.as_ref().maps();

    let user_mac_table_clone_2 = Arc::clone(&user_mac_table);
    builder
        .add(maps.new_discovered_entries_rb(), move |data| {
            new_discovered_entry_handler(data, user_mac_table_clone_2.as_ref().clone().unwrap())
        })
        .unwrap();



    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let user_mac_table_clone_3 = Arc::clone(&user_mac_table);
    while running.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::from_secs(5));
        println!("Content of the user_mac_table");
        for (key, value) in user_mac_table_clone_3.as_ref().iter() {
            // println!("the Key is {}, the value is {}", key.clone().as_ref(), value)
            println!("the Key is {:?}, the value is {:?}, the last registered time is {:?}", key.mac ,value.interface_index, value.timestamp)
        }
    }

    Ok(())
}

fn new_discovered_entry_handler(data: &[u8], user_mac_table: Cache<mac_address, iface_index>) -> ::std::os::raw::c_int {
    if data.len() != mem::size_of::<mac_address_iface_entry>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<mac_address_iface_entry>()
        );
        return 1;
    }

    let event = unsafe { &*(data.as_ptr() as *const mac_address_iface_entry) };


    user_mac_table.insert(event.mac.clone(), event.iface.clone());

    0
}
