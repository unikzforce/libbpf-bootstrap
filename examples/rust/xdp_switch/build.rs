use std::fs::create_dir_all;
use std::path::Path;

use libbpf_cargo::SkeletonBuilder;

const XDP_SWITCH_SRC: &str = "./src/bpf/xdp_switch.bpf.c";
const UNKNOWN_UNICAST_FLOODING_SRC: &str = "./src/bpf/unknown_unicast_flooding.bpf.c";

fn main() {
    // It's unfortunate we cannot use `OUT_DIR` to store the generated skeleton.
    // Reasons are because the generated skeleton contains compiler attributes
    // that cannot be `include!()`ed via macro. And we cannot use the `#[path = "..."]`
    // trick either because you cannot yet `concat!(env!("OUT_DIR"), "/skel.rs")` inside
    // the path attribute either (see https://github.com/rust-lang/rust/pull/83366).
    //
    // However, there is hope! When the above feature stabilizes we can clean this
    // all up.
    create_dir_all("./src/bpf/.output").unwrap();
    let xdp_switch_skel = Path::new("./src/bpf/.output/xdp_switch.skel.rs");
    SkeletonBuilder::new()
        .source(XDP_SWITCH_SRC)
        .build_and_generate(&xdp_switch_skel)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", XDP_SWITCH_SRC);

    let unknown_unicast_flooding_skel = Path::new("./src/bpf/.output/unknown_unicast_flooding.skel.rs");
    SkeletonBuilder::new()
        .source(UNKNOWN_UNICAST_FLOODING_SRC)
        .build_and_generate(&unknown_unicast_flooding_skel)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", UNKNOWN_UNICAST_FLOODING_SRC);
}
