use std::sync::atomic::{AtomicBool, Ordering};

use std::sync::Arc;
use std::mem;
use std::os::fd::{AsFd, AsRawFd};
use std::thread;
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

#[path = "bpf/.output/unknown_unicast_flooding.skel.rs"]
mod unknown_unicast_flooding;

use xdp_switch::*;

use chrono::Utc;
use libbpf_rs::{Link, MapFlags, RingBuffer, TC_INGRESS, TcHook, TcHookBuilder};
use moka::notification::RemovalCause;
use unsafe_send_sync::UnsafeSend;
use crate::unknown_unicast_flooding::{UnknownUnicastFloodingSkel, UnknownUnicastFloodingSkelBuilder};

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

    std::fs::remove_file("/sys/fs/bpf/mac_table")?;
    std::fs::remove_file("/sys/fs/bpf/new_discovered_entries_rb")?;

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

    let xdp_switch_skel_builder = XdpSwitchSkelBuilder::default();
    let xdp_switch_open_skel = xdp_switch_skel_builder.open()?;
    let xdp_switch_open_skel_unsafe_send = Arc::new(UnsafeSend::new(xdp_switch_open_skel.load()?));

    let xdp_switch_open_skel_unsafe_send_for_eviction_clone = Arc::clone(&xdp_switch_open_skel_unsafe_send);
    let eviction_listener = move |k: Arc<mac_address>, v: iface_index, _: RemovalCause| {
        println!("eviction_listener activated");
        let maps = xdp_switch_open_skel_unsafe_send_for_eviction_clone.as_ref().maps();
        let kernel_mac_table = maps.mac_table();
        let existing_kernel_entry = kernel_mac_table.lookup(&k.mac, MapFlags::ANY);

        match existing_kernel_entry {
            Ok(Some(data)) => {

                println!("eviction_listener: an entry found in kernel_mac_table");

                // The data is available, now we can try to convert it to iface_index struct
                if data.len() == mem::size_of::<iface_index>() {
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

    let network_interface_indices: Vec<u32> = filtered_network_interfaces
        .iter()
        .map(|iface| iface.index)
        .collect();
    let filtered_network_interfaces_count = filtered_network_interfaces.len();

    let unknown_unicast_flooding_skel_builder = UnknownUnicastFloodingSkelBuilder::default();
    let unknown_unicast_flooding_open_skel = unknown_unicast_flooding_skel_builder.open()?;
    let unknown_unicast_flooding_open_skel_loaded_unsafe_send = Arc::new(UnsafeSend::new(unknown_unicast_flooding_open_skel.load()?));

    let unknown_unicast_flooding_open_skel_unsafe_send_for_tc_hook_builder = Arc::clone(&unknown_unicast_flooding_open_skel_loaded_unsafe_send);
    let unknown_unicast_flooding_prog = unknown_unicast_flooding_open_skel_unsafe_send_for_tc_hook_builder.as_ref().progs();
    let mut tc_builder = TcHookBuilder::new(unknown_unicast_flooding_prog.unknown_unicast_flooding().as_fd());

    let xdp_switch_open_skel_unsafe_send_for_attach_clone = Arc::clone(&xdp_switch_open_skel_unsafe_send);
    let unknown_unicast_flooding_open_skel_unsafe_send_for_attach_clone = Arc::clone(&unknown_unicast_flooding_open_skel_loaded_unsafe_send);



    let mut xdp_tchook_link_tuples: Vec<(Link, TcHook)> = filtered_network_interfaces.iter().map(move |iface: &NetworkInterface| -> Result<(Link, TcHook), Box<dyn std::error::Error>> {
        let xdp_switch_skel_mut_ref: &mut UnsafeSend<XdpSwitchSkel> = unsafe {
            &mut *(Arc::as_ptr(&xdp_switch_open_skel_unsafe_send_for_attach_clone) as *mut _)
        };

        let unknown_unicast_flooding_skel_mut_ref: &mut UnsafeSend<UnknownUnicastFloodingSkel> = unsafe {
            &mut *(Arc::as_ptr(&unknown_unicast_flooding_open_skel_unsafe_send_for_attach_clone) as *mut _)
        };

        for i in 0..filtered_network_interfaces_count {
            unknown_unicast_flooding_skel_mut_ref.bss().interfaces[i] = network_interface_indices[i];
            unknown_unicast_flooding_skel_mut_ref.data().number_of_interfaces = filtered_network_interfaces_count as u32;
        }

        println!("trying to attach to network card {:?}", iface.name);
        let _xpd_switch_attachment_link = xdp_switch_skel_mut_ref.progs_mut().xdp_switch().attach_xdp(iface.index as i32)?;

        tc_builder
            .ifindex(iface.index as i32)
            .replace(true)
            .handle(1)
            .priority(1);
        let mut ingress = tc_builder.hook(TC_INGRESS);
        ingress.destroy();

        println!("trying to delete previous tc on interface {:?}", iface.name);

        let mut ingress = tc_builder.hook(TC_INGRESS);

        println!("trying to create tc on new interface {:?}", iface.name);
        ingress.create()?;

        println!("trying to attach tc on new interface {:?}", iface.name);
        let tc_hook_attached = ingress.attach()?;

        println!("successful attachment to network card {:?}", iface.name);
        Ok((_xpd_switch_attachment_link, tc_hook_attached))
    }).collect::<Result<Vec<(Link, TcHook)>, _>>()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;


    let skel_for_new_discoveries_clone = Arc::clone(&xdp_switch_open_skel_unsafe_send);
    let maps = skel_for_new_discoveries_clone.as_ref().maps();
    let user_mac_table_clone_2 = Arc::clone(&user_mac_table);

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(maps.new_discovered_entries_rb(), move |data| {
            new_discovered_entry_handler(data, user_mac_table_clone_2.as_ref().clone().unwrap())
        })?;

    let mgr = builder.build()?;


    let user_mac_table_clone_3 = Arc::clone(&user_mac_table);
    while running.load(Ordering::SeqCst) {
        mgr.poll(Duration::from_secs(5))?;
        println!("Content of the user_mac_table");
        for (key, value) in user_mac_table_clone_3.as_ref().iter() {
            // println!("the Key is {}, the value is {}", key.clone().as_ref(), value)
            println!("the Key is {:?}, the value is {:?}, the last registered time is {:?}", key.mac ,value.interface_index, value.timestamp)
        }
    }

    println!("starting to cleanup");


    for mut tuple in xdp_tchook_link_tuples {
        println!("trying to destroy tc in interfaces");
        tuple.1.destroy();
    }

    println!("trying to destroy remove mac_table map");
    std::fs::remove_file("/sys/fs/bpf/mac_table")?;

    println!("trying to destroy remove new_discovered_entries_rb ring buffer");
    std::fs::remove_file("/sys/fs/bpf/new_discovered_entries_rb")?;

    Ok(())
}

fn new_discovered_entry_handler(data: &[u8], user_mac_table: Cache<mac_address, iface_index>) -> std::os::raw::c_int {
    println!("Receieved new_discovered_entry message");
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
