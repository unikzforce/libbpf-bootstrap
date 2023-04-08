
#include "router.skel.h"
#include <sys/resource.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void bump_memloc_rlimit(void)
{
    struct rlimit rlimit_new = {
            .rlim_cur = RLIM_INFINITY,
            .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlimit_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOC limit\n");
        exit(1);
    }
}

void print_ifaces(void)
{
    // get a list of network interfaces
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // iterate over the list of network interfaces
    // print the interface name and index
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        int family = ifa->ifa_addr->sa_family;

        printf("%s\t%d\n", ifa->ifa_name, if_nametoindex(ifa->ifa_name));

//        if (family == AF_INET || family == AF_INET6) {
//            printf("%s\t%d", ifa->ifa_name, if_nametoindex(ifa->ifa_name));
//        }
    }

    freeifaddrs(ifaddr);
    fflush(stdout);
}

// create a main function that opens the skeleton, loads and attaches it, and then waits for a SIGINT signal to exit.
// it should also attach it to a network interface programmatically with libbpf.
int main(int argc, char **argv)
{

    struct router_bpf *skel;
    struct bpf_link *link;
    int err;
    sigset_t set;
    int sig;

    libbpf_set_print(libbpf_print_fn);

    print_ifaces();

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <DEV>", argv[0]);
        return 1;
    }

    int iface_index = if_nametoindex(argv[1]);

    // increase rlimit memlock
    bump_memloc_rlimit();

    // open the skeleton
    skel = router_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton");
        return 1;
    }

    // load and verify the BPF programs
    err = router_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton");
        goto cleanup;
    }

    // attach the BPF programs
    link = bpf_program__attach_xdp(skel->progs.xdp_router, iface_index);
    // replace libbpf_get_error with new method
    if (link == NULL) {
        fprintf(stderr, "Failed to attach BPF program");
        goto cleanup;
    }

    sigemptyset(&set);
    sigaddset(&set, SIGINT);

    sigwait(&set, &sig);


cleanup:
    // detach the BPF program from the interface
//    bpf_set_link_xdp_fd(skel->links.iface, -1, 0);
    if(link != NULL) {
        bpf_link__destroy(link);
    }

    // cleanup the skeleton
    router_bpf__destroy(skel);

    return -err;
}

//The router.c file is a bit more involved than the other examples. It contains a main function that opens the skeleton, loads and attaches it, and then waits for a SIGINT signal to exit. It also attaches the BPF program to a network interface programmatically with libbpf.
//
//The main function starts by increasing the rlimit memlock. This is required to increase the maximum amount of memory that can be locked into memory. This is needed because the BPF program will be loaded into memory.
//
//Next, the main function opens the skeleton. The skeleton is a structure that contains all the BPF programs and maps.


